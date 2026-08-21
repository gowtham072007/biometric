import os
import urllib.parse
from pathlib import Path
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

# Load environment variables from .env if present
env_path = Path(__file__).resolve().parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)

BASE_DIR = Path(__file__).resolve().parent.parent

def sanitize_database_url(url: str) -> str:
    """Sanitizes, URL-encodes passwords, and ensures IPv4 pooler usage for Supabase on IPv4-only hosts."""
    if not url:
        return None
    url = url.strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # Automatic IPv4 Pooler conversion for Supabase direct URLs (which are IPv6-only)
    if 'db.dfahwspvqdpdocivyeqy.supabase.co' in url or ('.supabase.co' in url and 'pooler' not in url):
        url = url.replace('db.dfahwspvqdpdocivyeqy.supabase.co', 'aws-0-ap-northeast-2.pooler.supabase.com')
        if '://postgres:' in url:
            url = url.replace('://postgres:', '://postgres.dfahwspvqdpdocivyeqy:')
        
    # Handle passwords with special characters (@, #, :, etc.)
    if '://' in url:
        scheme, rest = url.split('://', 1)
        if '@' in rest:
            userinfo, hostinfo = rest.rsplit('@', 1)
            if ':' in userinfo:
                username, password = userinfo.split(':', 1)
                raw_password = urllib.parse.unquote(password)
                encoded_password = urllib.parse.quote_plus(raw_password)
                return f"{scheme}://{username}:{encoded_password}@{hostinfo}"
    return url

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or "geofence_biometric_super_secret_key_change_in_production_2026"
    
    # Database Configuration (Supabase / PostgreSQL / SQLite)
    DATABASE_URL = sanitize_database_url(os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL") or os.getenv("POSTGRES_URL"))
    DATABASE_PATH = os.getenv("DATABASE_PATH") or ("/tmp/geofence_bio.db" if os.getenv("VERCEL") else str(BASE_DIR / "database" / "geofence_bio.db"))
    
    # MySQL Configuration (Legacy)
    MYSQL_HOST = os.getenv("MYSQL_HOST") or "localhost"
    MYSQL_USER = os.getenv("MYSQL_USER") or "root"
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD") or ""
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE") or "fxec_biometric"
    
    # Detect Vercel Serverless Environment
    IS_VERCEL = bool(os.getenv("VERCEL"))

    # WebAuthn Configuration
    # Automatically resolve domain from Vercel system variables if not explicitly provided
    _detected_host = os.getenv("VERCEL_PROJECT_PRODUCTION_URL") or os.getenv("VERCEL_URL")
    if _detected_host and "://" in _detected_host:
        _detected_host = urllib.parse.urlparse(_detected_host).netloc or _detected_host

    WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID") or _detected_host or "localhost"
    WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME") or "FXEC BIOMETRIC Auth System"
    WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN") or (
        f"https://{WEBAUTHN_RP_ID}" if (IS_VERCEL or _detected_host) else "http://localhost:5000"
    )
    
    # Default Geofence Config
    DEFAULT_LOCATION_NAME = os.getenv("DEFAULT_LOCATION_NAME") or "FXEC Campus Site"
    DEFAULT_LATITUDE = float(os.getenv("DEFAULT_LATITUDE") or "8.732309")
    DEFAULT_LONGITUDE = float(os.getenv("DEFAULT_LONGITUDE") or "77.723764")
    DEFAULT_RADIUS_METERS = float(os.getenv("DEFAULT_RADIUS_METERS") or "500.0")
    DEFAULT_MAX_GPS_ACCURACY = float(os.getenv("DEFAULT_MAX_GPS_ACCURACY") or "200.0")
    
    # Admin Seed Credentials
    ADMIN_USER_ID = os.getenv("ADMIN_USER_ID") or "admin"
    ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME") or "System Administrator"
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL") or "admin@geofence.local"
    ADMIN_PHONE = os.getenv("ADMIN_PHONE") or "+10000000000"
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD") or "Admin@123456"
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = (os.getenv("SESSION_COOKIE_SECURE") or str(IS_VERCEL)).lower() in ("true", "1", "t")
