# pyrefly: ignore [missing-import]
from flask import Blueprint, request, jsonify, session
from backend.models.schemas import (
    create_user, get_user_by_id, get_user_by_email, get_user_by_id_or_email,
    get_credentials_by_user, update_own_profile, verify_and_update_user_password,
    reset_user_password, generate_and_store_otp, verify_otp_and_reset_password,
    calculate_user_attendance_stats, get_user_latest_late_slip, update_late_slip_reason,
    get_device_by_user_id, bind_user_device, check_device_permission
)
from backend.utils.security import hash_password, verify_password, login_required, admin_required

auth_bp = Blueprint('auth', __name__, url_prefix='/api')

@auth_bp.route('/register', methods=['POST'])
@admin_required
def register():
    """Register a new user account (Admin only)."""
    data = request.get_json() or {}
    user_id = str(data.get('user_id', '') or '').strip()
    full_name = str(data.get('full_name', '') or '').strip()
    email = str(data.get('email', '') or '').strip()
    phone = str(data.get('phone', '') or '').strip()
    password = str(data.get('password', '') or '').strip()
    role = str(data.get('role', 'user') or 'user').strip().lower()

    if not user_id or not full_name or not email or not phone:
        return jsonify({'success': False, 'message': 'All fields (User ID, Full Name, Email, Phone) are required.'}), 400

    if role not in ['user', 'admin']:
        role = 'user'

    if not password:
        password = "PasskeyUser@2026"

    if get_user_by_id(user_id):
        return jsonify({'success': False, 'message': f'User ID "{user_id}" is already registered.'}), 400

    if get_user_by_email(email):
        return jsonify({'success': False, 'message': f'Email "{email}" is already registered.'}), 400

    try:
        pw_hash = hash_password(password)
        user = create_user(user_id, full_name, email, phone, pw_hash, role=role, status='active')

        return jsonify({
            'success': True,
            'message': 'Registration successful. User account created.',
            'user': {
                'user_id': user['user_id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'phone': user['phone'],
                'role': user['role']
            }
        }), 201
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Password login endpoint with 1-user-per-device verification."""
    data = request.get_json() or {}
    user_id_or_email = str(data.get('user_id', '') or '').strip()
    password = str(data.get('password', '') or '').strip()
    device_id = str(data.get('device_id', '') or request.headers.get('X-Device-Id', '') or '').strip()
    device_name = str(data.get('device_name', '') or '').strip()

    if not user_id_or_email or not password:
        return jsonify({'success': False, 'message': 'User ID / Email and password are required.'}), 400

    user = get_user_by_id_or_email(user_id_or_email)

    if not user or not verify_password(password, user['password_hash']):
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401

    if user['status'] == 'inactive':
        return jsonify({'success': False, 'message': 'Account is inactive. Please contact system administrator.'}), 403

    # Device binding check (Enforce 1 user per device & 1 device per user for non-admin accounts)
    is_admin = (user.get('role') == 'admin')
    if not is_admin and device_id:
        perm = check_device_permission(user['user_id'], device_id, is_admin=False)
        if not perm['allowed']:
            return jsonify({
                'success': False,
                'message': perm['reason'],
                'device_blocked': True
            }), 403

        try:
            bind_user_device(
                user_id=user['user_id'],
                device_id=device_id,
                device_name=device_name or "Smart Device",
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e), 'device_blocked': True}), 403

    session['user_id'] = user['user_id']
    session['role'] = user['role']
    session['full_name'] = user['full_name']
    if device_id:
        session['device_id'] = device_id

    bound_device = get_device_by_user_id(user['user_id'])

    return jsonify({
        'success': True,
        'message': 'Login successful.',
        'user': {
            'user_id': user['user_id'],
            'full_name': user['full_name'],
            'email': user['email'],
            'phone': user['phone'],
            'role': user['role'],
            'status': user['status'],
            'device': bound_device
        }
    })

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Clear active user session."""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully.'})

@auth_bp.route('/me', methods=['GET', 'PUT'])
def user_me():
    """Returns or updates details of the currently authenticated user in session."""
    if 'user_id' not in session:
        return jsonify({'authenticated': False, 'message': 'Not logged in.'}), 200 if request.method == 'GET' else 401

    user_id = session['user_id']

    if request.method == 'GET':
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            return jsonify({'authenticated': False}), 200

        creds = get_credentials_by_user(user['user_id'])
        has_webauthn = len(creds) > 0
        device = get_device_by_user_id(user['user_id'])

        return jsonify({
            'authenticated': True,
            'user': {
                'user_id': user['user_id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'phone': user['phone'],
                'role': user['role'],
                'status': user['status'],
                'has_webauthn': has_webauthn,
                'credential_count': len(creds),
                'device': device
            }
        })

    elif request.method == 'PUT':
        data = request.get_json() or {}
        full_name = data.get('full_name')
        email = data.get('email')
        phone = data.get('phone')

        try:
            updated = update_own_profile(user_id, full_name=full_name, email=email, phone=phone)
            session['full_name'] = updated['full_name']
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully.',
                'user': {
                    'user_id': updated['user_id'],
                    'full_name': updated['full_name'],
                    'email': updated['email'],
                    'phone': updated['phone'],
                    'role': updated['role']
                }
            })
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'Profile update failed: {str(e)}'}), 500

@auth_bp.route('/me/change-password', methods=['POST'])
@login_required
def change_password():
    """Allows authenticated user to change their account password."""
    data = request.get_json() or {}
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current password and new password are required.'}), 400

    try:
        verify_and_update_user_password(session['user_id'], current_password, new_password)
        return jsonify({'success': True, 'message': 'Password changed successfully.'})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Password change failed.'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password_route():
    """Resets user password via verified registered phone number."""
    data = request.get_json() or {}
    user_id = data.get('user_id', '').strip()
    phone = data.get('phone', '').strip()
    new_password = data.get('new_password', '').strip()

    if not user_id or not phone or not new_password:
        return jsonify({'success': False, 'message': 'User ID / Email, phone number, and new password are required.'}), 400

    try:
        reset_user_password(user_id, phone, new_password)
        return jsonify({'success': True, 'message': 'Password has been reset successfully. Please login with your new password.'})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Password reset failed: {str(e)}'}), 500

@auth_bp.route('/send-otp', methods=['POST'])
def send_otp_route():
    """Generates and sends a 6-digit OTP code to the registered phone number."""
    data = request.get_json() or {}
    user_id = data.get('user_id', '').strip()
    phone = data.get('phone', '').strip()

    if not user_id or not phone:
        return jsonify({'success': False, 'message': 'User ID / Email and phone number are required.'}), 400

    try:
        otp_info = generate_and_store_otp(user_id, phone)
        return jsonify({
            'success': True,
            'user_id': otp_info['user_id'],
            'demo_otp': otp_info['demo_otp'],
            'message': otp_info['message']
        })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send OTP: {str(e)}'}), 500

@auth_bp.route('/verify-otp-reset', methods=['POST'])
def verify_otp_reset_route():
    """Verifies OTP and resets the user's password."""
    data = request.get_json() or {}
    user_id = data.get('user_id', '').strip()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '').strip()

    if not user_id or not otp or not new_password:
        return jsonify({'success': False, 'message': 'User ID, OTP code, and new password are required.'}), 400

    try:
        verify_otp_and_reset_password(user_id, otp, new_password)
        return jsonify({'success': True, 'message': 'OTP verified! Password has been reset successfully.'})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'OTP verification failed: {str(e)}'}), 500

@auth_bp.route('/attendance/check/<user_id>', methods=['GET'])
def check_user_attendance(user_id):
    """Public pre-authentication attendance score preview."""
    user = get_user_by_id_or_email(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    stats = calculate_user_attendance_stats(user['user_id'])
    return jsonify({
        'success': True,
        'user_id': user['user_id'],
        'full_name': user['full_name'],
        'attendance_stats': stats
    })

@auth_bp.route('/late-slip/latest', methods=['GET'])
@login_required
def get_latest_late_slip_route():
    """Returns the latest late permission slip for the logged in user."""
    user_id = session.get('user_id')
    slip = get_user_latest_late_slip(user_id)
    return jsonify({'success': True, 'slip': slip})

@auth_bp.route('/late-slip/submit', methods=['POST'])
@login_required
def submit_late_slip_reason_route():
    """Submits explanation reason for a late arrival."""
    user_id = session.get('user_id')
    data = request.get_json() or {}
    slip_id = data.get('slip_id')
    reason = data.get('reason', '').strip()

    if not slip_id or not reason:
        return jsonify({'success': False, 'message': 'Slip ID and reason explanation are required.'}), 400

    try:
        updated = update_late_slip_reason(user_id, int(slip_id), reason)
        return jsonify({
            'success': True,
            'message': 'Late permission reason submitted successfully. Awaiting Administrator unblock.',
            'slip': updated
        })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Submission failed: {str(e)}'}), 500
