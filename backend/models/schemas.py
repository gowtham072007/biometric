import sqlite3
import random
import time as time_module
from datetime import datetime, time, timezone, timedelta
from backend.database import get_db_connection
from backend.utils.serializers import row_to_dict, rows_to_list

# In-memory OTP Store: { user_id: { 'otp': '123456', 'expires_at': timestamp, 'phone': phone } }
_OTP_STORE = {}

def get_ist_now() -> str:
    """Returns current date and time formatted in Indian Standard Time (IST, UTC+5:30)."""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')

def get_ist_today() -> str:
    """Returns current date formatted in Indian Standard Time (IST, UTC+5:30)."""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime('%Y-%m-%d')


# ==============================================================================
# User Model Operations
# ==============================================================================

def create_user(user_id: str, full_name: str, email: str, phone: str, password_hash: str, role: str = 'user', status: str = 'active') -> dict:
    if not user_id or not email:
        raise ValueError("User ID and Email are required.")

    u_id = str(user_id).strip()
    f_name = str(full_name).strip() if full_name else ''
    u_email = str(email).strip().lower()
    u_phone = str(phone).strip() if phone else ''
    clean_role = str(role).strip().lower() if role else 'user'
    clean_status = str(status).strip().lower() if status else 'active'

    if not f_name:
        raise ValueError("Full Name is required.")
    if not u_phone:
        raise ValueError("Phone Number is required.")
    if clean_role not in ['user', 'admin']:
        clean_role = 'user'
    if clean_status not in ['active', 'inactive', 'blocked_late']:
        clean_status = 'active'

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (user_id, full_name, email, phone, role, status, password_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (u_id, f_name, u_email, u_phone, clean_role, clean_status, password_hash))
        conn.commit()
        return get_user_by_id(u_id)
    except Exception as e:
        conn.rollback()
        err_msg = str(e).lower()
        if 'unique' in err_msg or 'duplicate' in err_msg or 'already exists' in err_msg:
            raise ValueError("User ID or Email already exists.") from e
        raise e
    finally:
        conn.close()

def get_user_by_id(user_id: str) -> dict:
    if user_id is None:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (str(user_id).strip(),))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def get_user_by_email(email: str) -> dict:
    if email is None:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (str(email).strip(),))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def get_user_by_id_or_email(identifier: str) -> dict:
    if not identifier:
        return None
    clean = str(identifier).strip()
    user = get_user_by_id(clean)
    if not user:
        user = get_user_by_email(clean)
    return user

def get_all_users(search_query: str = None, status_filter: str = None, role_filter: str = None, sort_by: str = None) -> list:
    """Returns a list of all users with passkey count, present days, attendance percentage, and last auth."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(DISTINCT DATE(timestamp)) FROM authentication_logs WHERE result = 'SUCCESS'")
    row_days = cursor.fetchone()
    total_system_days = row_days[0] if row_days and row_days[0] else 1

    query = """
        SELECT u.id, u.user_id, u.full_name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
               COUNT(DISTINCT c.id) as credential_count,
               COUNT(DISTINCT CASE WHEN l.result = 'SUCCESS' THEN DATE(l.timestamp) END) as present_days,
               MAX(l.timestamp) as last_auth_time
        FROM users u
        LEFT JOIN webauthn_credentials c ON u.user_id = c.user_id
        LEFT JOIN authentication_logs l ON u.user_id = l.user_id
        WHERE 1=1
    """
    params = []

    if search_query:
        query += " AND (u.full_name LIKE ? OR u.email LIKE ? OR u.user_id LIKE ? OR u.phone LIKE ?)"
        pattern = f"%{search_query.strip()}%"
        params.extend([pattern, pattern, pattern, pattern])

    if status_filter and status_filter.lower() != 'all':
        query += " AND u.status = ?"
        params.append(status_filter.lower())

    if role_filter and role_filter.lower() != 'all':
        query += " AND u.role = ?"
        params.append(role_filter.lower())

    query += " GROUP BY u.id"

    # Sorting
    if sort_by == 'name_asc':
        query += " ORDER BY u.full_name ASC"
    elif sort_by == 'name_desc':
        query += " ORDER BY u.full_name DESC"
    elif sort_by == 'user_id_asc':
        query += " ORDER BY u.user_id ASC"
    elif sort_by == 'user_id_desc':
        query += " ORDER BY u.user_id DESC"
    elif sort_by == 'attendance_asc':
        query += " ORDER BY present_days ASC"
    elif sort_by == 'attendance_desc':
        query += " ORDER BY present_days DESC"
    else:
        query += " ORDER BY u.created_at DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    user_list = rows_to_list(rows)
    for u in user_list:
        p_days = u.get('present_days', 0) or 0
        pct = round((p_days / total_system_days) * 100, 1) if total_system_days > 0 else 0.0
        u['attendance_percentage'] = min(100.0, pct)
        u['total_working_days'] = total_system_days

    return user_list

def get_user_full_details(user_id: str) -> dict:
    """Returns detailed user profile including credentials, attendance summary, today's punch, logs, and late slips."""
    user = get_user_by_id(user_id)
    if not user:
        return None

    # Remove sensitive password hash from user output
    user_data = dict(user)
    user_data.pop('password_hash', None)

    creds = get_credentials_by_user(user['user_id'])
    stats = calculate_user_attendance_stats(user['user_id'])
    punch_today = get_user_punch_info_today(user['user_id'])
    recent_logs = get_user_logs(user['user_id'], limit=15)
    late_slip = get_user_latest_late_slip(user['user_id'])

    return {
        'user': user_data,
        'credentials': creds,
        'attendance_stats': stats,
        'today_punch': punch_today,
        'recent_logs': recent_logs,
        'late_slip': late_slip
    }

def update_user_status(user_id: str, status: str) -> bool:
    clean_status = str(status).strip().lower()
    if clean_status not in ['active', 'inactive', 'blocked_late']:
        raise ValueError("Invalid status. Must be 'active', 'inactive', or 'blocked_late'.")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (clean_status, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def update_user_details(user_id: str, new_user_id: str = None, full_name: str = None, email: str = None, phone: str = None, role: str = None, status: str = None, new_password: str = None) -> dict:
    from backend.utils.security import hash_password

    user = get_user_by_id(user_id)
    if not user:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()

    target_user_id = user_id

    # Handle User ID change & cascade update across tables atomically
    if new_user_id is not None:
        clean_new_id = str(new_user_id).strip()
        if not clean_new_id:
            conn.close()
            raise ValueError("User ID / Roll No cannot be empty.")
        if clean_new_id != user_id:
            if user_id == 'admin':
                conn.close()
                raise ValueError("Default system admin User ID cannot be changed.")
            existing_user = get_user_by_id(clean_new_id)
            if existing_user:
                conn.close()
                raise ValueError(f"User ID '{clean_new_id}' is already registered to another account.")

            try:
                # Temporarily disable foreign keys for manual cascading update in SQLite
                cursor.execute("PRAGMA foreign_keys = OFF;")
                cursor.execute("UPDATE users SET user_id = ? WHERE user_id = ?", (clean_new_id, user_id))
                cursor.execute("UPDATE webauthn_credentials SET user_id = ? WHERE user_id = ?", (clean_new_id, user_id))
                cursor.execute("UPDATE authentication_logs SET user_id = ? WHERE user_id = ?", (clean_new_id, user_id))
                cursor.execute("UPDATE late_permission_slips SET user_id = ? WHERE user_id = ?", (clean_new_id, user_id))
                cursor.execute("PRAGMA foreign_keys = ON;")
                target_user_id = clean_new_id
            except Exception as e:
                conn.rollback()
                conn.close()
                raise ValueError(f"Failed to update User ID: {str(e)}") from e

    updates = []
    params = []

    if full_name is not None:
        clean_name = str(full_name).strip()
        if not clean_name:
            conn.close()
            raise ValueError("Full Name cannot be empty.")
        updates.append("full_name = ?")
        params.append(clean_name)

    if email is not None:
        clean_email = str(email).strip().lower()
        if not clean_email:
            conn.close()
            raise ValueError("Email Address cannot be empty.")
        existing_email = get_user_by_email(clean_email)
        if existing_email and existing_email['user_id'] != target_user_id:
            conn.close()
            raise ValueError(f"Email '{clean_email}' is already registered to another user.")
        updates.append("email = ?")
        params.append(clean_email)

    if phone is not None:
        clean_phone = str(phone).strip()
        if not clean_phone:
            conn.close()
            raise ValueError("Phone Number cannot be empty.")
        updates.append("phone = ?")
        params.append(clean_phone)

    if role is not None:
        clean_role = str(role).strip().lower()
        if clean_role not in ['user', 'admin']:
            conn.close()
            raise ValueError("Invalid role. Must be 'user' or 'admin'.")
        updates.append("role = ?")
        params.append(clean_role)

    if status is not None:
        clean_status = str(status).strip().lower()
        if clean_status not in ['active', 'inactive', 'blocked_late']:
            conn.close()
            raise ValueError("Invalid status. Must be 'active', 'inactive', or 'blocked_late'.")
        updates.append("status = ?")
        params.append(clean_status)

    if new_password is not None and str(new_password).strip():
        pw_hash = hash_password(str(new_password).strip())
        updates.append("password_hash = ?")
        params.append(pw_hash)

    if updates:
        updates.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?"
        params.append(target_user_id)
        cursor.execute(query, params)

    conn.commit()
    conn.close()
    return get_user_by_id(target_user_id)

def update_own_profile(user_id: str, full_name: str = None, email: str = None, phone: str = None) -> dict:
    """Updates user's own profile (full name, email, phone) without role/status changes."""
    user = get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found.")

    conn = get_db_connection()
    cursor = conn.cursor()

    updates = []
    params = []

    if full_name is not None:
        clean_name = str(full_name).strip()
        if not clean_name:
            conn.close()
            raise ValueError("Full Name cannot be empty.")
        updates.append("full_name = ?")
        params.append(clean_name)

    if email is not None:
        clean_email = str(email).strip().lower()
        if not clean_email:
            conn.close()
            raise ValueError("Email cannot be empty.")
        existing_email = get_user_by_email(clean_email)
        if existing_email and existing_email['user_id'] != user_id:
            conn.close()
            raise ValueError(f"Email '{clean_email}' is already in use by another account.")
        updates.append("email = ?")
        params.append(clean_email)

    if phone is not None:
        clean_phone = str(phone).strip()
        if not clean_phone:
            conn.close()
            raise ValueError("Phone number cannot be empty.")
        updates.append("phone = ?")
        params.append(clean_phone)

    if updates:
        updates.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?"
        params.append(user_id)
        cursor.execute(query, params)
        conn.commit()

    conn.close()
    return get_user_by_id(user_id)

def delete_user(user_id: str) -> bool:
    if user_id == 'admin':
        raise ValueError("Default system admin cannot be deleted.")

    conn = get_db_connection()
    cursor = conn.cursor()
    # Explicitly delete related records to be completely safe
    cursor.execute("DELETE FROM webauthn_credentials WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM authentication_logs WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM late_permission_slips WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def reset_user_password(user_id_or_email: str, phone: str, new_password: str) -> dict:
    """Verifies user by User ID/Email and phone number, then resets their account password."""
    user = verify_user_phone(user_id_or_email, phone)
    return update_user_password_direct(user['user_id'], new_password)

def verify_user_phone(user_id_or_email: str, phone: str) -> dict:
    """Verifies user exists and phone matches registered user record."""
    clean_id = str(user_id_or_email).strip()
    clean_phone = str(phone).strip()

    if not clean_id or not clean_phone:
        raise ValueError("User ID / Email and Phone Number are required.")

    user = get_user_by_id(clean_id)
    if not user:
        user = get_user_by_email(clean_id)

    if not user:
        raise ValueError(f"User ID or Email '{clean_id}' was not found.")

    user_phone = str(user.get('phone', '') or '').strip()
    if not user_phone:
        raise ValueError("No phone number registered for this account. Please contact system administrator.")

    digits_input = ''.join(filter(str.isdigit, clean_phone))
    digits_user = ''.join(filter(str.isdigit, user_phone))

    if not digits_input or (digits_input not in digits_user and digits_user not in digits_input):
        raise ValueError("Registered phone number verification failed. Please enter your registered phone number.")

    return user

def update_user_password_direct(user_id: str, new_password: str) -> dict:
    """Updates user password hash directly by user_id."""
    from backend.utils.security import hash_password

    clean_pw = str(new_password).strip()
    if not clean_pw:
        raise ValueError("New password cannot be empty.")

    pw_hash = hash_password(clean_pw)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (pw_hash, user_id))
    conn.commit()
    conn.close()

    return get_user_by_id(user_id)

def verify_and_update_user_password(user_id: str, current_password: str, new_password: str) -> bool:
    """Verifies user's current password before changing to new password."""
    from backend.utils.security import verify_password, hash_password

    user = get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found.")

    if not verify_password(current_password, user['password_hash']):
        raise ValueError("Current password is incorrect.")

    clean_new = str(new_password).strip()
    if not clean_new or len(clean_new) < 6:
        raise ValueError("New password must be at least 6 characters long.")

    pw_hash = hash_password(clean_new)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (pw_hash, user_id))
    conn.commit()
    conn.close()
    return True

# ==============================================================================
# OTP Password Reset Management
# ==============================================================================

def generate_and_store_otp(user_id_or_email: str, phone: str) -> dict:
    """Verifies phone and generates a 6-digit OTP code valid for 10 minutes."""
    user = verify_user_phone(user_id_or_email, phone)
    u_id = user['user_id']

    # Generate 6-digit OTP
    otp_code = f"{random.randint(100000, 999999)}"
    expires_at = time_module.time() + 600 # 10 minutes

    _OTP_STORE[u_id] = {
        'otp': otp_code,
        'expires_at': expires_at,
        'phone': phone,
        'attempts': 0
    }

    return {
        'user_id': u_id,
        'full_name': user['full_name'],
        'phone': user['phone'],
        'demo_otp': otp_code,
        'message': f"OTP sent to {user['phone'][-4:].rjust(len(user['phone']), '*')}."
    }

def verify_otp_and_reset_password(user_id_or_email: str, otp: str, new_password: str) -> dict:
    """Verifies OTP and updates the user's password."""
    user = get_user_by_id_or_email(user_id_or_email)
    if not user:
        raise ValueError("User not found.")

    u_id = user['user_id']
    record = _OTP_STORE.get(u_id)

    if not record:
        raise ValueError("No OTP request found. Please request a new OTP.")

    if time_module.time() > record['expires_at']:
        _OTP_STORE.pop(u_id, None)
        raise ValueError("OTP has expired. Please request a new OTP.")

    if record.get('attempts', 0) >= 5:
        _OTP_STORE.pop(u_id, None)
        raise ValueError("Too many failed attempts. Please request a new OTP.")

    if str(record['otp']).strip() != str(otp).strip():
        record['attempts'] = record.get('attempts', 0) + 1
        raise ValueError("Invalid 6-digit OTP code.")

    # OTP is valid -> reset password & remove OTP
    _OTP_STORE.pop(u_id, None)
    return update_user_password_direct(u_id, new_password)


# ==============================================================================
# Punch & Attendance Operations
# ==============================================================================

def get_user_punch_info_today(user_id: str) -> dict:
    """Returns Punch In and Punch Out status for today in IST."""
    conn = get_db_connection()
    cursor = conn.cursor()
    ist_today = get_ist_today()

    cursor.execute("""
        SELECT timestamp FROM authentication_logs
        WHERE user_id = ? AND result = 'SUCCESS' AND DATE(timestamp) = ?
        ORDER BY timestamp ASC
    """, (user_id, ist_today))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {
            'today_date': ist_today,
            'punch_in': None,
            'punch_out': None,
            'next_punch_type': 'PUNCH_IN',
            'punch_count': 0
        }

    punch_in = rows[0]['timestamp']
    punch_out = rows[-1]['timestamp'] if len(rows) > 1 else None

    return {
        'today_date': ist_today,
        'punch_in': str(punch_in) if punch_in else None,
        'punch_out': str(punch_out) if punch_out else None,
        'next_punch_type': 'PUNCH_OUT',
        'punch_count': len(rows)
    }

def calculate_periods_status(punch_in: str, punch_out: str) -> list:
    """
    Calculates attendance status for Periods 1 through 7:
    - 1st Punch (Punch IN): Grants Present status for the first four periods (P1, P2, P3, P4).
    - 2nd Punch (Punch OUT): Evaluates subsequent periods (P5, P6, P7).
      If Punch OUT time >= period start time, period is marked Present; otherwise Absent.
    """
    if not punch_in:
        return [{'period': i, 'status': 'ABSENT', 'label': f'P{i}'} for i in range(1, 8)]

    try:
        t_out = punch_out.time() if isinstance(punch_out, datetime) else (datetime.strptime(punch_out, '%Y-%m-%d %H:%M:%S').time() if punch_out else None)

        period_times = [
            (1, time(9, 0), time(9, 50)),
            (2, time(9, 50), time(10, 40)),
            (3, time(10, 55), time(11, 45)),
            (4, time(11, 45), time(12, 35)),
            (5, time(13, 20), time(14, 10)),
            (6, time(14, 10), time(15, 0)),
            (7, time(15, 15), time(16, 5)),
        ]

        result = []
        for p_num, p_start, p_end in period_times:
            if p_num <= 4:
                # First 4 periods marked PRESENT upon Punch IN
                result.append({'period': p_num, 'status': 'PRESENT', 'label': f'P{p_num}'})
            else:
                # Periods 5, 6, 7 marked PRESENT if Punch OUT time >= period start time
                if t_out is not None and t_out >= p_start:
                    result.append({'period': p_num, 'status': 'PRESENT', 'label': f'P{p_num}'})
                else:
                    result.append({'period': p_num, 'status': 'ABSENT', 'label': f'P{p_num}'})
        return result
    except Exception:
        return [{'period': i, 'status': 'PRESENT' if i <= 4 else 'ABSENT', 'label': f'P{i}'} for i in range(1, 8)]

def process_daily_absentees(target_date: str = None) -> dict:
    """
    Records ABSENT status for active users who did not punch in on target_date (default: today in IST).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    t_date = str(target_date).strip() if target_date else get_ist_today()

    cursor.execute("SELECT user_id, full_name, email FROM users WHERE role = 'user' AND status = 'active'")
    active_users = rows_to_list(cursor.fetchall())

    marked_count = 0
    present_count = 0
    absent_count = 0

    for u in active_users:
        u_id = u['user_id']
        cursor.execute("""
            SELECT COUNT(*) FROM authentication_logs
            WHERE user_id = ? AND result = 'SUCCESS' AND DATE(timestamp) = ?
        """, (u_id, t_date))
        row_s = cursor.fetchone()
        has_success = (row_s[0] > 0) if row_s else False

        if has_success:
            present_count += 1
        else:
            absent_count += 1
            cursor.execute("""
                SELECT COUNT(*) FROM authentication_logs
                WHERE user_id = ? AND result = 'ABSENT' AND DATE(timestamp) = ?
            """, (u_id, t_date))
            row_a = cursor.fetchone()
            already_marked = (row_a[0] > 0) if row_a else False

            if not already_marked:
                absent_timestamp = f"{t_date} 23:59:59"
                cursor.execute("""
                    INSERT INTO authentication_logs (
                        user_id, timestamp, latitude, longitude, gps_accuracy,
                        calculated_distance, result, failure_reason
                    )
                    VALUES (?, ?, 0.0, 0.0, 0.0, 0.0, 'ABSENT', 'User did not punch in (Marked Absent)')
                """, (u_id, absent_timestamp))
                marked_count += 1

    conn.commit()
    conn.close()

    return {
        'target_date': t_date,
        'total_active_users': len(active_users),
        'present_count': present_count,
        'absent_count': absent_count,
        'newly_marked_absent': marked_count
    }

def get_user_daily_summary(user_id: str, limit_days: int = 30) -> list:
    """Aggregates attendance logs by day to return Punch In, Punch Out, total duration, 1 to 7 period attendance, including ABSENT status when user did not punch."""
    process_daily_absentees()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT DATE(timestamp) as log_date
        FROM authentication_logs
        ORDER BY log_date DESC
        LIMIT ?
    """, (limit_days,))
    rows = cursor.fetchall()

    if not rows:
        conn.close()
        return []

    summary = []
    for r in rows:
        d = r['log_date']
        cursor.execute("""
            SELECT MIN(timestamp) as punch_in,
                   MAX(timestamp) as max_time,
                   COUNT(*) as total_punches
            FROM authentication_logs
            WHERE user_id = ? AND result = 'SUCCESS' AND DATE(timestamp) = ?
        """, (user_id, d))
        p_row = cursor.fetchone()

        p_in = p_row['punch_in'] if p_row and p_row['punch_in'] else None
        total_punches = p_row['total_punches'] if p_row and p_row['total_punches'] else 0
        p_out = p_row['max_time'] if (p_row and p_row['max_time'] and total_punches > 1) else None

        if p_in:
            duration_str = None
            if p_out:
                try:
                    t1 = p_in if isinstance(p_in, datetime) else datetime.strptime(p_in, '%Y-%m-%d %H:%M:%S')
                    t2 = p_out if isinstance(p_out, datetime) else datetime.strptime(p_out, '%Y-%m-%d %H:%M:%S')
                    diff_sec = int((t2 - t1).total_seconds())
                    hrs = diff_sec // 3600
                    mins = (diff_sec % 3600) // 60
                    duration_str = f"{hrs}h {mins}m"
                except Exception:
                    duration_str = None

            periods_info = calculate_periods_status(p_in, p_out)
            summary.append({
                'date': str(d),
                'status': 'PRESENT',
                'punch_in': p_in,
                'punch_out': p_out,
                'total_punches': total_punches,
                'duration': duration_str,
                'periods': periods_info
            })
        else:
            periods_info = [{'period': i, 'status': 'ABSENT', 'label': f'P{i}'} for i in range(1, 8)]
            summary.append({
                'date': str(d),
                'status': 'ABSENT',
                'punch_in': None,
                'punch_out': None,
                'total_punches': 0,
                'duration': '--',
                'periods': periods_info
            })

    conn.close()
    return summary

def calculate_user_attendance_stats(user_id: str) -> dict:
    """Calculates attendance metrics, percentage, and today's Punch In / Punch Out for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(DISTINCT DATE(timestamp)) FROM authentication_logs")
    row_t = cursor.fetchone()
    total_system_days = row_t[0] if row_t and row_t[0] else 1

    cursor.execute("""
        SELECT COUNT(DISTINCT DATE(timestamp)) FROM authentication_logs
        WHERE user_id = ? AND result = 'SUCCESS'
    """, (user_id,))
    row_p = cursor.fetchone()
    present_days = row_p[0] if row_p and row_p[0] else 0

    absent_days = max(0, total_system_days - present_days)

    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE user_id = ?", (user_id,))
    row_att = cursor.fetchone()
    total_attempts = row_att[0] if row_att and row_att[0] else 0

    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE user_id = ? AND result = 'SUCCESS'", (user_id,))
    row_succ = cursor.fetchone()
    success_attempts = row_succ[0] if row_succ and row_succ[0] else 0

    pct = round((present_days / total_system_days) * 100, 1) if total_system_days > 0 else 0.0
    pct = min(100.0, pct)

    conn.close()

    today_info = get_user_punch_info_today(user_id)

    return {
        'present_days': present_days,
        'absent_days': absent_days,
        'total_working_days': total_system_days,
        'attendance_percentage': pct,
        'total_attempts': total_attempts,
        'successful_attempts': success_attempts,
        'today_punch_in': today_info['punch_in'],
        'today_punch_out': today_info['punch_out'],
        'next_punch_type': today_info['next_punch_type'],
        'today_punch_count': today_info['punch_count']
    }


# ==============================================================================
# Late Permission Slip Operations
# ==============================================================================

def record_late_punch_in(user_id: str, in_time: str) -> dict:
    """Sets user status to 'blocked_late' and creates a late permission slip."""
    conn = get_db_connection()
    cursor = conn.cursor()
    ist_today = get_ist_today()

    cursor.execute("""
        UPDATE users
        SET status = 'blocked_late', updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (user_id,))

    cursor.execute("""
        SELECT * FROM late_permission_slips
        WHERE user_id = ? AND date = ?
    """, (user_id, ist_today))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO late_permission_slips (user_id, date, in_time, reason, status)
            VALUES (?, ?, ?, 'Pending late reason form submission', 'PENDING_APPROVAL')
        """, (user_id, ist_today, in_time))

    conn.commit()
    conn.close()
    return get_user_latest_late_slip(user_id)

def get_user_latest_late_slip(user_id: str) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT lps.*, u.full_name, u.email, u.phone
        FROM late_permission_slips lps
        JOIN users u ON lps.user_id = u.user_id
        WHERE lps.user_id = ?
        ORDER BY lps.id DESC LIMIT 1
    """, (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def update_late_slip_reason(user_id: str, slip_id: int, reason: str) -> dict:
    clean_reason = str(reason).strip()
    if not clean_reason:
        raise ValueError("Please provide a valid reason for late arrival.")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE late_permission_slips
        SET reason = ?
        WHERE id = ? AND user_id = ?
    """, (clean_reason, slip_id, user_id))
    conn.commit()
    conn.close()
    return get_user_latest_late_slip(user_id)

def get_all_pending_late_slips() -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT lps.*, u.full_name, u.email, u.phone, u.status as user_status
        FROM late_permission_slips lps
        JOIN users u ON lps.user_id = u.user_id
        ORDER BY lps.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows_to_list(rows)

def admin_unblock_late_user(user_id: str, admin_id: str = 'admin') -> bool:
    """Removes late block from user account and approves their late permission slip."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET status = 'active', updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (user_id,))

    cursor.execute("""
        UPDATE late_permission_slips
        SET status = 'APPROVED', approved_by = ?, approved_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND status = 'PENDING_APPROVAL'
    """, (admin_id, user_id))

    conn.commit()
    conn.close()
    return True


# ==============================================================================
# WebAuthn Credentials Model Operations
# ==============================================================================

def create_credential(user_id: str, credential_id: str, public_key: str, sign_count: int = 0, credential_name: str = "SmartDevice Passkey") -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, credential_name)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, credential_id, public_key, sign_count, credential_name))
    conn.commit()
    cursor.execute("SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def get_credentials_by_user(user_id: str) -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_list(rows)

def get_credential_by_id(credential_id: str) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def update_credential_sign_count(credential_id: str, new_sign_count: int) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE webauthn_credentials
        SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
    """, (new_sign_count, credential_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def delete_credential(user_id: str, credential_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM webauthn_credentials
        WHERE user_id = ? AND credential_id = ?
    """, (user_id, credential_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


# ==============================================================================
# Geofence Settings Model Operations
# ==============================================================================

def get_geofence_settings() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM geofence_settings ORDER BY id ASC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def update_geofence_settings(location_name: str, latitude: float, longitude: float, radius_meters: float, max_gps_accuracy_meters: float = 50.0, is_demo_mode: bool = False) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM geofence_settings ORDER BY id ASC LIMIT 1")
    row = cursor.fetchone()

    demo_val = 1 if is_demo_mode else 0
    if row:
        cursor.execute("""
            UPDATE geofence_settings
            SET location_name = ?, latitude = ?, longitude = ?, radius_meters = ?, max_gps_accuracy_meters = ?, is_demo_mode = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (location_name.strip(), latitude, longitude, radius_meters, max_gps_accuracy_meters, demo_val, row['id']))
    else:
        cursor.execute("""
            INSERT INTO geofence_settings (location_name, latitude, longitude, radius_meters, max_gps_accuracy_meters, is_demo_mode)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (location_name.strip(), latitude, longitude, radius_meters, max_gps_accuracy_meters, demo_val))

    conn.commit()
    conn.close()
    return get_geofence_settings()


# ==============================================================================
# Authentication Logs Model Operations
# ==============================================================================

def log_authentication_event(user_id: str, latitude: float, longitude: float, gps_accuracy: float, calculated_distance: float, result: str, failure_reason: str = None, credential_id: str = None, ip_address: str = None, user_agent: str = None) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    ist_time = get_ist_now()
    cursor.execute("""
        INSERT INTO authentication_logs (user_id, timestamp, latitude, longitude, gps_accuracy, calculated_distance, result, failure_reason, credential_id, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, ist_time, latitude, longitude, gps_accuracy, calculated_distance, result, failure_reason, credential_id, ip_address, user_agent))
    conn.commit()
    log_id = getattr(cursor, 'lastrowid', None)
    if log_id:
        cursor.execute("SELECT * FROM authentication_logs WHERE id = ?", (log_id,))
    else:
        cursor.execute("SELECT * FROM authentication_logs WHERE user_id = ? AND timestamp = ? ORDER BY id DESC LIMIT 1", (user_id, ist_time))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)

def get_user_logs(user_id: str, limit: int = 100) -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM authentication_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_list(rows)

def get_admin_logs(date_filter: str = None, status_filter: str = None, search: str = None, limit: int = 500) -> list:
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT l.*, u.full_name, u.email
        FROM authentication_logs l
        LEFT JOIN users u ON l.user_id = u.user_id
        WHERE 1=1
    """
    params = []

    ist_now_dt = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    ist_today = ist_now_dt.strftime('%Y-%m-%d')
    if date_filter == 'today':
        query += " AND DATE(l.timestamp) = ?"
        params.append(ist_today)
    elif date_filter == 'yesterday':
        yesterday_str = (ist_now_dt - timedelta(days=1)).strftime('%Y-%m-%d')
        query += " AND DATE(l.timestamp) = ?"
        params.append(yesterday_str)
    elif date_filter == 'last_7_days':
        seven_days_str = (ist_now_dt - timedelta(days=7)).strftime('%Y-%m-%d')
        query += " AND DATE(l.timestamp) >= ?"
        params.append(seven_days_str)
    elif date_filter == 'last_30_days':
        thirty_days_str = (ist_now_dt - timedelta(days=30)).strftime('%Y-%m-%d')
        query += " AND DATE(l.timestamp) >= ?"
        params.append(thirty_days_str)

    if status_filter and status_filter.lower() != 'all':
        query += " AND l.result = ?"
        params.append(status_filter.upper())

    if search:
        query += " AND (u.full_name LIKE ? OR u.email LIKE ? OR l.user_id LIKE ?)"
        pattern = f"%{search.strip()}%"
        params.extend([pattern, pattern, pattern])

    query += " ORDER BY l.timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows_to_list(rows)

def get_dashboard_stats() -> dict:
    process_daily_absentees()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'user'")
    row_u = cursor.fetchone()
    total_users = row_u[0] if row_u else 0

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'user' AND status = 'active'")
    row_au = cursor.fetchone()
    active_users = row_au[0] if row_au else 0

    ist_today = get_ist_today()

    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE DATE(timestamp) = ? AND result = 'SUCCESS'", (ist_today,))
    row_ts = cursor.fetchone()
    today_success = row_ts[0] if row_ts else 0

    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE DATE(timestamp) = ? AND result = 'ABSENT'", (ist_today,))
    row_ta = cursor.fetchone()
    today_absent = row_ta[0] if row_ta else 0

    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE DATE(timestamp) = ? AND result NOT IN ('SUCCESS', 'ABSENT')", (ist_today,))
    row_tf = cursor.fetchone()
    today_failed = row_tf[0] if row_tf else 0

    cursor.execute("""
        SELECT COUNT(DISTINCT user_id) FROM authentication_logs
        WHERE DATE(timestamp) = ? AND result = 'SUCCESS'
    """, (ist_today,))
    row_ui = cursor.fetchone()
    users_inside_today = row_ui[0] if row_ui else 0

    # Calculate average attendance percentage across all active users
    cursor.execute("SELECT COUNT(DISTINCT DATE(timestamp)) FROM authentication_logs WHERE result = 'SUCCESS'")
    row_tot = cursor.fetchone()
    total_system_days = row_tot[0] if row_tot and row_tot[0] else 1

    cursor.execute("""
        SELECT COUNT(DISTINCT DATE(l.timestamp)) as present_count
        FROM users u
        LEFT JOIN authentication_logs l ON u.user_id = l.user_id AND l.result = 'SUCCESS'
        WHERE u.role = 'user' AND u.status = 'active'
        GROUP BY u.user_id
    """)
    user_presents = cursor.fetchall()
    if user_presents:
        pcts = [min(100.0, round((r['present_count'] / total_system_days) * 100, 1)) for r in user_presents]
        avg_pct = round(sum(pcts) / len(pcts), 1)
    else:
        avg_pct = 0.0

    conn.close()
    return {
        'total_users': total_users,
        'active_users': active_users,
        'today_success': today_success,
        'today_absent': today_absent,
        'today_failed': today_failed,
        'users_inside_today': users_inside_today,
        'avg_attendance_percentage': avg_pct
    }
