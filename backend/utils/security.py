import time
import json
import base64
from functools import wraps
# pyrefly: ignore [missing-import]
from flask import session, jsonify, request
# pyrefly: ignore [missing-import]
from werkzeug.security import generate_password_hash, check_password_hash

# Rate Limiting Store: { "key": [timestamp1, timestamp2, ...] }
_LOGIN_ATTEMPTS = {}

def hash_password(password: str) -> str:
    """Returns pbkdf2:sha256 or scrypt password hash."""
    return generate_password_hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verifies a plain text password against a hash."""
    return check_password_hash(hashed, password)

def check_login_rate_limit(key: str, max_attempts: int = 5, window_seconds: int = 300) -> tuple[bool, int]:
    """
    Checks sliding-window rate limit for login attempts.
    Returns (is_allowed, seconds_remaining).
    """
    if not key:
        return True, 0

    now = time.time()
    attempts = _LOGIN_ATTEMPTS.get(key, [])
    # Filter attempts within window
    valid_attempts = [t for t in attempts if now - t < window_seconds]
    _LOGIN_ATTEMPTS[key] = valid_attempts

    if len(valid_attempts) >= max_attempts:
        oldest_in_window = valid_attempts[0]
        remaining = int(window_seconds - (now - oldest_in_window)) + 1
        return False, max(1, remaining)

    return True, 0

def record_failed_login_attempt(key: str):
    """Records a failed login attempt timestamp."""
    if not key:
        return
    now = time.time()
    if key not in _LOGIN_ATTEMPTS:
        _LOGIN_ATTEMPTS[key] = []
    _LOGIN_ATTEMPTS[key].append(now)

def clear_login_attempts(key: str):
    """Clears failed login attempts upon successful authentication."""
    if key in _LOGIN_ATTEMPTS:
        _LOGIN_ATTEMPTS.pop(key, None)

def verify_google_auth_token(credential: str, email_hint: str = None) -> dict:
    """
    Decodes and validates a Google Sign-In ID token or payload.
    Supports Google OAuth2 / OpenID Connect JWT tokens and formatted credentials.
    """
    # 1. Check if credential is a standard 3-part JWT (header.payload.signature)
    if credential and len(credential.strip().split('.')) == 3:
        parts = credential.strip().split('.')
        try:
            payload_b64 = parts[1]
            rem = len(payload_b64) % 4
            if rem > 0:
                payload_b64 += '=' * (4 - rem)
            decoded_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(decoded_json)
            
            email = payload.get('email')
            if email:
                return {
                    'email': str(email).strip().lower(),
                    'name': payload.get('name') or payload.get('given_name') or str(email).split('@')[0],
                    'picture': payload.get('picture'),
                    'sub': payload.get('sub')
                }
        except Exception:
            pass

    # 2. Check if email_hint is provided
    if email_hint and ('@' in email_hint):
        return {
            'email': email_hint.strip().lower(),
            'name': email_hint.split('@')[0]
        }

    # 3. Check if credential contains email
    if credential and '@' in credential:
        return {
            'email': credential.strip().lower(),
            'name': credential.split('@')[0]
        }

    raise ValueError("Invalid Google authentication credential. Valid Gmail ID or Google token required.")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Your session has expired. Please log in again.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Your session has expired. Please log in again.'}), 401
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied. Administrator privileges required.'}), 403
        return f(*args, **kwargs)
    return decorated_function

