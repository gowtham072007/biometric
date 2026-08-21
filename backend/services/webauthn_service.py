import json
# pyrefly: ignore [missing-import]
import webauthn
# pyrefly: ignore [missing-import]
from flask import has_request_context, request
# pyrefly: ignore [missing-import]
from webauthn.helpers import structs
from backend.config import Config
from backend.utils.serializers import bytes_to_base64url, base64url_to_bytes

def get_current_rp_id(rp_id: str = None) -> str:
    """Returns the effective WebAuthn Relying Party ID matching current domain or config."""
    if rp_id:
        return rp_id
    if has_request_context():
        host = request.host.split(':')[0]
        if host:
            return host
    return Config.WEBAUTHN_RP_ID or "localhost"

def get_current_origin(origin: str = None) -> str:
    """Returns the effective WebAuthn origin matching current request or config."""
    if origin:
        return origin
    if has_request_context():
        req_origin = request.headers.get('Origin')
        if req_origin:
            return req_origin
        scheme = request.headers.get('X-Forwarded-Proto', request.scheme or 'http')
        return f"{scheme}://{request.host}"
    return Config.WEBAUTHN_ORIGIN or "http://localhost:5000"

def get_webauthn_registration_options(user_id: str, full_name: str, existing_credentials=None, rp_id: str = None):
    """
    Generates WebAuthn registration options for a user.
    Returns (options_json_str, challenge_base64url_str)
    """
    effective_rp_id = get_current_rp_id(rp_id) or "localhost"
    rp_name = Config.WEBAUTHN_RP_NAME or "FXEC BIOMETRIC Auth System"
    clean_user_id = str(user_id or 'user').strip()
    clean_display_name = str(full_name or clean_user_id or 'User').strip()
    user_id_bytes = clean_user_id.encode('utf-8')
    
    exclude_credentials = []
    if existing_credentials:
        for cred in existing_credentials:
            cred_id_bytes = base64url_to_bytes(cred['credential_id'])
            exclude_credentials.append(
                structs.PublicKeyCredentialDescriptor(id=cred_id_bytes)
            )

    options = webauthn.generate_registration_options(
        rp_id=effective_rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=clean_user_id,
        user_display_name=clean_display_name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=structs.AuthenticatorSelectionCriteria(
            user_verification=structs.UserVerificationRequirement.PREFERRED,
            resident_key=structs.ResidentKeyRequirement.PREFERRED
        )
    )

    challenge_b64 = bytes_to_base64url(options.challenge)
    options_json = webauthn.options_to_json(options)
    
    return options_json, challenge_b64

def verify_webauthn_registration(credential_payload, expected_challenge_b64: str, rp_id: str = None, origin: str = None):
    """
    Verifies the WebAuthn registration response sent by the client.
    Returns (verified_credential_id_b64, verified_public_key_b64, initial_sign_count)
    """
    effective_rp_id = get_current_rp_id(rp_id)
    effective_origin = get_current_origin(origin)
    expected_challenge_bytes = base64url_to_bytes(expected_challenge_b64)
    
    # Accept JSON string or dict
    if isinstance(credential_payload, dict):
        credential_str = json.dumps(credential_payload)
    else:
        credential_str = credential_payload

    verification = webauthn.verify_registration_response(
        credential=credential_str,
        expected_challenge=expected_challenge_bytes,
        expected_rp_id=effective_rp_id,
        expected_origin=effective_origin,
        require_user_verification=False
    )

    cred_id_b64 = bytes_to_base64url(verification.credential_id)
    public_key_b64 = bytes_to_base64url(verification.credential_public_key)
    sign_count = verification.sign_count

    return cred_id_b64, public_key_b64, sign_count

def get_webauthn_authentication_options(user_credentials, rp_id: str = None):
    """
    Generates WebAuthn authentication assertion options.
    Returns (options_json_str, challenge_base64url_str)
    """
    effective_rp_id = get_current_rp_id(rp_id) or "localhost"
    allow_credentials = []
    if user_credentials:
        for cred in user_credentials:
            cred_id_bytes = base64url_to_bytes(cred['credential_id'])
            allow_credentials.append(
                structs.PublicKeyCredentialDescriptor(id=cred_id_bytes)
            )

    options = webauthn.generate_authentication_options(
        rp_id=effective_rp_id,
        allow_credentials=allow_credentials,
        user_verification=structs.UserVerificationRequirement.PREFERRED
    )

    challenge_b64 = bytes_to_base64url(options.challenge)
    options_json = webauthn.options_to_json(options)

    return options_json, challenge_b64

def verify_webauthn_authentication(credential_payload, expected_challenge_b64: str, public_key_b64: str, current_sign_count: int, rp_id: str = None, origin: str = None):
    """
    Verifies the WebAuthn authentication assertion response.
    Returns new_sign_count.
    """
    effective_rp_id = get_current_rp_id(rp_id) or "localhost"
    effective_origin = get_current_origin(origin)
    expected_challenge_bytes = base64url_to_bytes(expected_challenge_b64)
    public_key_bytes = base64url_to_bytes(public_key_b64)

    if isinstance(credential_payload, dict):
        credential_str = json.dumps(credential_payload)
    else:
        credential_str = credential_payload

    verification = webauthn.verify_authentication_response(
        credential=credential_str,
        expected_challenge=expected_challenge_bytes,
        expected_rp_id=effective_rp_id,
        expected_origin=effective_origin,
        credential_public_key=public_key_bytes,
        credential_current_sign_count=current_sign_count,
        require_user_verification=False
    )

    return verification.new_sign_count
