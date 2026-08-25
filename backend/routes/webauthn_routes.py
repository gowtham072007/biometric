import json
# pyrefly: ignore [missing-import]
from flask import Blueprint, request, jsonify, session
from backend.models.schemas import (
    get_user_by_id, get_credentials_by_user, create_credential,
    get_credential_by_id, update_credential_sign_count,
    get_geofence_settings, log_authentication_event, get_user_punch_info_today,
    check_device_permission, bind_user_device, get_device_by_user_id
)
from backend.services.geofence import verify_location
from backend.services.webauthn_service import (
    get_webauthn_registration_options, verify_webauthn_registration,
    get_webauthn_authentication_options, verify_webauthn_authentication
)

webauthn_bp = Blueprint('webauthn', __name__, url_prefix='/api/webauthn')

@webauthn_bp.route('/register/options', methods=['POST'])
def register_options():
    """Generates WebAuthn registration options for the current or specified user."""
    data = request.get_json() or {}
    user_id = data.get('user_id') or session.get('user_id')
    device_id = str(data.get('device_id', '') or request.headers.get('X-Device-Id', '') or '').strip()

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required to register a passkey.'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User account not found.'}), 404

    # Enforce 1-user-per-device verification
    if user.get('role') != 'admin' and device_id:
        perm = check_device_permission(user['user_id'], device_id, is_admin=False)
        if not perm['allowed']:
            return jsonify({
                'success': False,
                'message': perm['reason'],
                'device_blocked': True
            }), 403

    existing_creds = get_credentials_by_user(user['user_id'])
    
    try:
        options_json, challenge_b64 = get_webauthn_registration_options(
            user['user_id'], user['full_name'], existing_creds
        )
        session['reg_challenge'] = challenge_b64
        session['reg_user_id'] = user['user_id']
        if device_id:
            session['reg_device_id'] = device_id

        return jsonify({
            'success': True,
            'options': json.loads(options_json),
            'user_id': user['user_id'],
            'full_name': user['full_name']
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to generate registration options: {str(e)}'}), 500


@webauthn_bp.route('/register/verify', methods=['POST'])
def register_verify():
    """Verifies client WebAuthn registration response and persists public key & device binding."""
    data = request.get_json() or {}
    credential_payload = data.get('credential')
    credential_name = data.get('credential_name', 'SmartDevice Passkey')
    user_id = data.get('user_id') or session.get('reg_user_id') or session.get('user_id')
    device_id = str(data.get('device_id', '') or session.get('reg_device_id', '') or request.headers.get('X-Device-Id', '') or '').strip()
    device_name = data.get('device_name') or credential_name
    
    challenge = session.get('reg_challenge')

    if not credential_payload or not challenge or not user_id:
        return jsonify({'success': False, 'message': 'Invalid registration state or missing challenge.'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    # Enforce device check before completing registration
    if user.get('role') != 'admin' and device_id:
        perm = check_device_permission(user['user_id'], device_id, is_admin=False)
        if not perm['allowed']:
            return jsonify({
                'success': False,
                'message': perm['reason'],
                'device_blocked': True
            }), 403

    try:
        cred_id_b64, public_key_b64, sign_count = verify_webauthn_registration(
            credential_payload, challenge
        )
        
        # Save credential in database
        cred = create_credential(
            user_id=user_id,
            credential_id=cred_id_b64,
            public_key=public_key_b64,
            sign_count=sign_count,
            credential_name=credential_name
        )

        # Bind device to user
        if device_id and user.get('role') != 'admin':
            bind_user_device(
                user_id=user_id,
                device_id=device_id,
                device_name=device_name,
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )

        session.pop('reg_challenge', None)
        session.pop('reg_user_id', None)
        session.pop('reg_device_id', None)

        return jsonify({
            'success': True,
            'message': 'Passkey registered successfully! You can now authenticate using your smartphone biometric.',
            'credential_id': cred['credential_id'],
            'user_id': user_id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Biometric registration verification failed: {str(e)}'}), 400


@webauthn_bp.route('/login/options', methods=['POST'])
def login_options():
    """
    Validates server-side geofence AND device binding BEFORE generating authentication challenge options.
    """
    data = request.get_json() or {}
    user_id = data.get('user_id') or session.get('user_id')
    lat = data.get('latitude')
    lon = data.get('longitude')
    accuracy = data.get('accuracy')
    device_id = str(data.get('device_id', '') or request.headers.get('X-Device-Id', '') or '').strip()

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required for authentication.'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User account not found.'}), 404

    if user['status'] != 'active':
        log_authentication_event(
            user_id=user['user_id'], latitude=lat, longitude=lon, gps_accuracy=accuracy,
            calculated_distance=0, result='FAILED', failure_reason='Inactive User Account',
            ip_address=request.remote_addr, user_agent=request.user_agent.string
        )
        return jsonify({'success': False, 'message': 'User account is inactive.'}), 403

    # Device binding check (Enforce 1 user per device & 1 device per user for non-admin accounts)
    if user.get('role') != 'admin' and device_id:
        perm = check_device_permission(user['user_id'], device_id, is_admin=False)
        if not perm['allowed']:
            log_authentication_event(
                user_id=user['user_id'], latitude=lat, longitude=lon, gps_accuracy=accuracy,
                calculated_distance=0, result='DEVICE_MISMATCH', failure_reason=perm['reason'],
                ip_address=request.remote_addr, user_agent=request.user_agent.string
            )
            return jsonify({
                'success': False,
                'reason': 'DEVICE_MISMATCH',
                'message': perm['reason'],
                'device_blocked': True
            }), 403

    # Check user passkeys
    user_creds = get_credentials_by_user(user['user_id'])
    if not user_creds:
        return jsonify({'success': False, 'message': 'No biometric passkey registered for this account. Please register a passkey first.'}), 400

    # SERVER-SIDE INDEPENDENT GEOFENCE VALIDATION
    geofence = get_geofence_settings()
    loc_result = verify_location(lat, lon, accuracy, geofence)

    if not loc_result['is_inside']:
        # Log failure event to database
        log_authentication_event(
            user_id=user['user_id'],
            latitude=lat,
            longitude=lon,
            gps_accuracy=accuracy,
            calculated_distance=loc_result.get('distance_meters', 0),
            result='OUTSIDE_RADIUS' if loc_result['status'] == 'OUTSIDE_RADIUS' else 'LOCATION_DENIED',
            failure_reason=loc_result['message'],
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        return jsonify({
            'success': False,
            'reason': loc_result['status'],
            'message': loc_result['message'],
            'distance_meters': loc_result.get('distance_meters'),
            'required_radius': loc_result['required_radius']
        }), 403

    # Geofence check passed: Generate WebAuthn options
    try:
        options_json, challenge_b64 = get_webauthn_authentication_options(user_creds)
        session['auth_challenge'] = challenge_b64
        session['auth_user_id'] = user['user_id']
        session['auth_lat'] = lat
        session['auth_lon'] = lon
        session['auth_accuracy'] = accuracy
        session['auth_distance'] = loc_result.get('distance_meters')
        if device_id:
            session['auth_device_id'] = device_id

        return jsonify({
            'success': True,
            'location_verified': True,
            'distance_meters': loc_result.get('distance_meters'),
            'required_radius': loc_result['required_radius'],
            'options': json.loads(options_json)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to generate authentication options: {str(e)}'}), 500


@webauthn_bp.route('/login/verify', methods=['POST'])
def login_verify():
    """
    Verifies client WebAuthn assertion response and records attendance event.
    """
    data = request.get_json() or {}
    credential_payload = data.get('credential')
    device_id = str(data.get('device_id', '') or session.get('auth_device_id', '') or request.headers.get('X-Device-Id', '') or '').strip()
    
    challenge = session.get('auth_challenge')
    user_id = session.get('auth_user_id') or session.get('user_id')
    lat = session.get('auth_lat') if session.get('auth_lat') is not None else data.get('latitude')
    lon = session.get('auth_lon') if session.get('auth_lon') is not None else data.get('longitude')
    accuracy = session.get('auth_accuracy') if session.get('auth_accuracy') is not None else data.get('accuracy')
    distance = session.get('auth_distance') if session.get('auth_distance') is not None else data.get('distance')

    if not credential_payload or not challenge or not user_id:
        log_authentication_event(
            user_id=user_id or 'unknown', latitude=lat, longitude=lon, gps_accuracy=accuracy,
            calculated_distance=distance if distance is not None else 0, result='BIOMETRIC_FAILED',
            failure_reason='Missing challenge or authentication session state',
            ip_address=request.remote_addr, user_agent=request.user_agent.string
        )
        return jsonify({'success': False, 'message': 'Invalid authentication session or missing challenge.'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    # Device binding check during assertion verify
    if user.get('role') != 'admin' and device_id:
        perm = check_device_permission(user['user_id'], device_id, is_admin=False)
        if not perm['allowed']:
            log_authentication_event(
                user_id=user['user_id'], latitude=lat, longitude=lon, gps_accuracy=accuracy,
                calculated_distance=distance or 0, result='DEVICE_MISMATCH', failure_reason=perm['reason'],
                ip_address=request.remote_addr, user_agent=request.user_agent.string
            )
            return jsonify({
                'success': False,
                'reason': 'DEVICE_MISMATCH',
                'message': perm['reason'],
                'device_blocked': True
            }), 403

    # Find credential ID from payload
    cred_raw_id = None
    if isinstance(credential_payload, dict):
        cred_raw_id = credential_payload.get('id')
    
    if not cred_raw_id:
        return jsonify({'success': False, 'message': 'Invalid credential response payload format.'}), 400

    stored_cred = get_credential_by_id(cred_raw_id)
    if not stored_cred:
        log_authentication_event(
            user_id=user_id, latitude=lat, longitude=lon, gps_accuracy=accuracy,
            calculated_distance=distance or 0, result='BIOMETRIC_FAILED',
            failure_reason='Unrecognized credential ID',
            ip_address=request.remote_addr, user_agent=request.user_agent.string
        )
        return jsonify({'success': False, 'message': 'Credential not registered for this account.'}), 400

    # VERIFY WEBAUTHN ASSERTION SIGNATURE
    try:
        new_sign_count = verify_webauthn_authentication(
            credential_payload=credential_payload,
            expected_challenge_b64=challenge,
            public_key_b64=stored_cred['public_key'],
            current_sign_count=stored_cred['sign_count']
        )
        
        # Update sign count
        update_credential_sign_count(stored_cred['credential_id'], new_sign_count)
        
        # Log successful attendance/authentication event
        log_authentication_event(
            user_id=user['user_id'],
            latitude=lat,
            longitude=lon,
            gps_accuracy=accuracy,
            calculated_distance=distance or 0,
            result='SUCCESS',
            failure_reason=None,
            credential_id=stored_cred['credential_id'],
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )

        # Bind or update last active device
        if device_id and user.get('role') != 'admin':
            try:
                bind_user_device(
                    user_id=user['user_id'],
                    device_id=device_id,
                    user_agent=request.user_agent.string,
                    ip_address=request.remote_addr
                )
            except Exception:
                pass

        # Retrieve updated Punch In / Punch Out status
        punch_info = get_user_punch_info_today(user['user_id'])
        current_punch_type = 'PUNCH_OUT' if punch_info['punch_count'] > 1 else 'PUNCH_IN'

        # Check if Punch IN is LATE (after 09:15:00 AM IST)
        is_late = False
        if current_punch_type == 'PUNCH_IN' and punch_info['punch_in']:
            punch_time_str = punch_info['punch_in'].split(' ')[1] if ' ' in punch_info['punch_in'] else punch_info['punch_in']
            if punch_time_str > '09:15:00':
                is_late = True
                from backend.models.schemas import record_late_punch_in
                record_late_punch_in(user['user_id'], punch_info['punch_in'])

        # Set user session
        session['user_id'] = user['user_id']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        if device_id:
            session['device_id'] = device_id

        # Clear challenge
        session.pop('auth_challenge', None)
        session.pop('auth_device_id', None)

        msg = f"Biometric Punch IN successful at {punch_info['punch_in']}!" if current_punch_type == 'PUNCH_IN' else f"Biometric Punch OUT successful at {punch_info['punch_out']}!"
        if is_late:
            msg = f"⚠️ LATE PUNCH IN DETECTED ({punch_info['punch_in']})! Your account is blocked until Late Permission PDF Form is submitted & Admin unblocks."

        return jsonify({
            'success': True,
            'message': msg,
            'is_late': is_late,
            'redirect': '/late_form.html' if is_late else '/history.html',
            'punch_type': current_punch_type,
            'punch_in_time': punch_info['punch_in'],
            'punch_out_time': punch_info['punch_out'],
            'user': {
                'user_id': user['user_id'],
                'full_name': user['full_name'],
                'role': user['role']
            },
            'location_info': {
                'latitude': lat,
                'longitude': lon,
                'distance_meters': distance
            }
        })
    except Exception as e:
        log_authentication_event(
            user_id=user_id, latitude=lat, longitude=lon, gps_accuracy=accuracy,
            calculated_distance=distance or 0, result='BIOMETRIC_FAILED',
            failure_reason=f'WebAuthn assertion failed: {str(e)}',
            credential_id=stored_cred['credential_id'],
            ip_address=request.remote_addr, user_agent=request.user_agent.string
        )
        return jsonify({'success': False, 'message': f'Biometric verification failed: {str(e)}'}), 400


@webauthn_bp.route('/credentials', methods=['GET'])
def get_user_credentials():
    """Returns registered passkeys for the logged in user."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    creds = get_credentials_by_user(user_id)
    return jsonify({'success': True, 'credentials': creds})

@webauthn_bp.route('/credentials/<credential_id>', methods=['DELETE'])
def delete_user_credential(credential_id):
    """Deletes a passkey for the logged in user."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    from backend.models.schemas import delete_credential
    success = delete_credential(user_id, credential_id)
    if success:
        return jsonify({'success': True, 'message': 'Passkey removed successfully.'})
    else:
        return jsonify({'success': False, 'message': 'Passkey not found or you do not have permission to delete it.'}), 404
