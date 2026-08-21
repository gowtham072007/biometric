import sqlite3
import os
from pathlib import Path
from backend.config import Config

try:
    # pyrefly: ignore [missing-import]
    import psycopg2
    # pyrefly: ignore [missing-import]
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

def is_postgres():
    return bool(Config.DATABASE_URL and Config.DATABASE_URL.startswith("postgres"))

class DBRow(dict):
    """
    Unified database row that supports both key-based access (row['col'])
    and index-based access (row[0], row[1]) for 100% compatibility with SQLite & PostgreSQL.
    """
    def __init__(self, data=None):
        if data:
            clean_data = {}
            for k, v in data.items():
                if hasattr(v, 'isoformat') and not isinstance(v, str):
                    clean_data[k] = str(v)
                else:
                    clean_data[k] = v
            super().__init__(clean_data)
            self._values = list(clean_data.values())
        else:
            super().__init__()
            self._values = []

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        return super().__getitem__(item)

    def get(self, key, default=None):
        if isinstance(key, int):
            try:
                return self._values[key]
            except IndexError:
                return default
        return super().get(key, default)

class PostgresCursorWrapper:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        if query.strip().upper().startswith('PRAGMA'):
            return None
        if params is not None:
            # Convert ? placeholders to %s for PostgreSQL compatibility
            query = query.replace('?', '%s')
            return self._cursor.execute(query, params)
        return self._cursor.execute(query)

    def fetchone(self):
        row = self._cursor.fetchone()
        return DBRow(row) if row is not None else None

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [DBRow(r) for r in rows] if rows else []

    def close(self):
        self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def __getattr__(self, name):
        return getattr(self._cursor, name)

class PostgresConnectionWrapper:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor(cursor_factory=RealDictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def execute(self, query, params=None):
        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()

def get_db_connection(db_path=None):
    """Establishes and returns a connection to Supabase / PostgreSQL or SQLite database."""
    if is_postgres():
        if not PSYCOPG2_AVAILABLE:
            raise RuntimeError("psycopg2 is required to connect to PostgreSQL / Supabase.")
        try:
            raw_conn = psycopg2.connect(Config.DATABASE_URL, connect_timeout=15)
            return PostgresConnectionWrapper(raw_conn)
        except Exception as e:
            print(f"[DB ERROR] PostgreSQL connection failed ({e}). Falling back to SQLite.")

    # Fallback to SQLite
    if db_path is None:
        db_path = Config.DATABASE_PATH
        
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(db_file), timeout=15.0)
    conn.row_factory = sqlite3.Row
    if Config.IS_VERCEL:
        conn.execute("PRAGMA journal_mode = DELETE;")
    else:
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path=None):
    """Initializes database schema for Supabase / PostgreSQL or SQLite."""
    if is_postgres():
        _init_postgres_db()
    else:
        _init_sqlite_db(db_path)

def _init_postgres_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table: users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(100) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(50) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: webauthn_credentials
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        transports VARCHAR(255),
        credential_name VARCHAR(255) DEFAULT 'SmartDevice Passkey',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)

    # Table: geofence_settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS geofence_settings (
        id SERIAL PRIMARY KEY,
        location_name VARCHAR(255) NOT NULL,
        latitude DOUBLE PRECISION NOT NULL,
        longitude DOUBLE PRECISION NOT NULL,
        radius_meters DOUBLE PRECISION NOT NULL,
        max_gps_accuracy_meters DOUBLE PRECISION NOT NULL DEFAULT 50.0,
        is_demo_mode INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: authentication_logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS authentication_logs (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        gps_accuracy DOUBLE PRECISION,
        calculated_distance DOUBLE PRECISION,
        result VARCHAR(50) NOT NULL,
        failure_reason TEXT,
        credential_id TEXT,
        ip_address VARCHAR(100),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: late_permission_slips
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS late_permission_slips (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        date VARCHAR(20) NOT NULL,
        in_time VARCHAR(20) NOT NULL,
        reason TEXT,
        status VARCHAR(50) NOT NULL DEFAULT 'PENDING_APPROVAL',
        approved_by VARCHAR(100),
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Seed Default Geofence Settings if empty
    cursor.execute("SELECT COUNT(*) as count FROM geofence_settings")
    row = cursor.fetchone()
    count = row.get('count', 0) if isinstance(row, dict) else 0
    if count == 0:
        cursor.execute("""
            INSERT INTO geofence_settings (location_name, latitude, longitude, radius_meters, max_gps_accuracy_meters, is_demo_mode)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            Config.DEFAULT_LOCATION_NAME,
            Config.DEFAULT_LATITUDE,
            Config.DEFAULT_LONGITUDE,
            Config.DEFAULT_RADIUS_METERS,
            Config.DEFAULT_MAX_GPS_ACCURACY
        ))
        conn.commit()

    cursor.close()
    conn.close()

def _init_sqlite_db(db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Table: users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        status TEXT NOT NULL DEFAULT 'active',
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: webauthn_credentials
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        credential_name TEXT DEFAULT 'SmartDevice Passkey',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)

    # Table: geofence_settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS geofence_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        location_name TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        radius_meters REAL NOT NULL,
        max_gps_accuracy_meters REAL NOT NULL DEFAULT 50.0,
        is_demo_mode INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: authentication_logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS authentication_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        latitude REAL,
        longitude REAL,
        gps_accuracy REAL,
        calculated_distance REAL,
        result TEXT NOT NULL,
        failure_reason TEXT,
        credential_id TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table: late_permission_slips
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS late_permission_slips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        date TEXT NOT NULL,
        in_time TEXT NOT NULL,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
        approved_by TEXT,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Seed Default Geofence Settings if empty
    cursor.execute("SELECT COUNT(*) FROM geofence_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO geofence_settings (location_name, latitude, longitude, radius_meters, max_gps_accuracy_meters, is_demo_mode)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            Config.DEFAULT_LOCATION_NAME,
            Config.DEFAULT_LATITUDE,
            Config.DEFAULT_LONGITUDE,
            Config.DEFAULT_RADIUS_METERS,
            Config.DEFAULT_MAX_GPS_ACCURACY
        ))
        conn.commit()

    cursor.close()
    conn.close()
