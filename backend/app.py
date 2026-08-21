import sys
import os
from pathlib import Path

# Add workspace root to python path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# pyrefly: ignore [missing-import]
from flask import Flask, send_from_directory, jsonify, session
# pyrefly: ignore [missing-import]
from flask_cors import CORS
# pyrefly: ignore [missing-import]
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.config import Config
from backend.database import init_db
from backend.models.schemas import get_user_by_id, create_user, get_user_logs, calculate_user_attendance_stats, get_user_daily_summary
from backend.utils.security import hash_password, login_required

# Blueprints
from backend.routes.auth_routes import auth_bp
from backend.routes.webauthn_routes import webauthn_bp
from backend.routes.geofence_routes import geofence_bp
from backend.routes.admin_routes import admin_bp

def create_app():
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
    static_dir = Path(__file__).resolve().parent.parent / "static"

    app = Flask(__name__, static_folder=str(frontend_dir), static_url_path="")
    app.config.from_object(Config)

    # Enable ProxyFix to correctly interpret reverse proxy headers (Vercel, Nginx, etc.)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Enable CORS for local development and session credentials
    cors_origins = [o for o in set([Config.WEBAUTHN_ORIGIN, "http://localhost:5000", "http://127.0.0.1:5000"]) if o]
    CORS(app, supports_credentials=True, origins=cors_origins)

    # Initialize SQLite Database
    init_db()

    # Seed Default Admin Account if missing
    seed_admin_user()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(webauthn_bp)
    app.register_blueprint(geofence_bp)
    app.register_blueprint(admin_bp)

    # User History Endpoint
    @app.route('/api/user/history', methods=['GET'])
    @login_required
    def user_history():
        user_id = session['user_id']
        logs = get_user_logs(user_id)
        stats = calculate_user_attendance_stats(user_id)
        daily_summary = get_user_daily_summary(user_id)
        return jsonify({'success': True, 'logs': logs, 'stats': stats, 'daily_summary': daily_summary})

    # Serve PWA manifest and service worker from static directory
    @app.route('/manifest.json')
    def serve_manifest():
        return send_from_directory(str(static_dir), 'manifest.json')

    @app.route('/service-worker.js')
    def serve_service_worker():
        return send_from_directory(str(static_dir), 'service-worker.js', mimetype='application/javascript')

    @app.route('/icons/<path:filename>')
    def serve_icons(filename):
        return send_from_directory(str(static_dir / 'icons'), filename)

    # Serve HTML Frontend Pages
    @app.route('/')
    def serve_index():
        if session.get('user_id'):
            return send_from_directory(str(frontend_dir), 'dashboard.html' if session.get('role') != 'admin' else 'admin.html')
        return send_from_directory(str(frontend_dir), 'login.html')

    @app.route('/<path:filename>')
    def serve_frontend_files(filename):
        target_path = frontend_dir / filename
        if target_path.exists() and not target_path.is_dir():
            return send_from_directory(str(frontend_dir), filename)
        # Fallback to index.html for SPA / client routes if present
        index_path = frontend_dir / 'index.html'
        if index_path.exists():
            return send_from_directory(str(frontend_dir), 'index.html')
        return jsonify({'error': 'Not found'}), 404

    return app

def seed_admin_user():
    """Seeds default admin user if not already in the database."""
    admin_id = Config.ADMIN_USER_ID
    if not get_user_by_id(admin_id):
        pw_hash = hash_password(Config.ADMIN_PASSWORD)
        try:
            create_user(
                user_id=admin_id,
                full_name=Config.ADMIN_FULL_NAME,
                email=Config.ADMIN_EMAIL,
                phone=Config.ADMIN_PHONE,
                password_hash=pw_hash,
                role='admin',
                status='active'
            )
            print(f"[SEED] Seeded admin user: '{admin_id}' ({Config.ADMIN_EMAIL})")
        except Exception as e:
            print(f"[SEED ERROR] Failed to seed admin user: {e}")

app = create_app()

if __name__ == '__main__':
    print(f"Starting FXEC BIOMETRIC App Server on {Config.WEBAUTHN_ORIGIN} ...")
    app.run(host='0.0.0.0', port=5000, debug=True)
