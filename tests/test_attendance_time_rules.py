import pytest
from datetime import datetime, timezone, timedelta
from backend.config import Config
from backend.app import create_app
from backend.models.schemas import (
    create_user, delete_user, validate_attendance_time_window,
    log_authentication_event, get_user_punch_info_today
)

@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_time_rules.db"
    Config.DATABASE_PATH = str(db_file)
    
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        yield client

def test_validate_attendance_time_window_unit():
    delete_user('timerule_user')
    create_user('timerule_user', 'Time Test User', 'time@test.edu', '+1234567890', 'hash')

    ist = timezone(timedelta(hours=5, minutes=30))
    today_str = datetime.now(ist).strftime('%Y-%m-%d')

    # 1. In Time before 9:01 AM (e.g., 08:59:00 AM) -> Allowed
    t_in_valid = datetime.strptime(f"{today_str} 08:59:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_in_valid)
    assert res['allowed'] is True
    assert res['punch_type'] == 'PUNCH_IN'
    assert res['reason'] is None

    # 2. In Time at 09:01:00 AM -> Rejected: "In Time is allowed only before 9:01 AM."
    t_in_901 = datetime.strptime(f"{today_str} 09:01:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_in_901)
    assert res['allowed'] is False
    assert res['punch_type'] == 'PUNCH_IN'
    assert res['reason'] == 'In Time is allowed only before 9:01 AM.'

    # 3. In Time after 09:01 AM (e.g., 10:30:00 AM) -> Rejected: "In Time is allowed only before 9:01 AM."
    t_in_late = datetime.strptime(f"{today_str} 10:30:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_in_late)
    assert res['allowed'] is False
    assert res['punch_type'] == 'PUNCH_IN'
    assert res['reason'] == 'In Time is allowed only before 9:01 AM.'

    # Simulate Punch In has occurred
    log_authentication_event('timerule_user', 13.0, 80.0, 10.0, 5.0, 'SUCCESS')

    # 4. Out Time at 12:00:00 PM -> Rejected: "Out Time is allowed only after 4:04 PM."
    t_out_noon = datetime.strptime(f"{today_str} 12:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_out_noon)
    assert res['allowed'] is False
    assert res['punch_type'] == 'PUNCH_OUT'
    assert res['reason'] == 'Out Time is allowed only after 4:04 PM.'

    # 5. Out Time at 04:04:00 PM (16:04:00) -> Rejected: "Out Time is allowed only after 4:04 PM."
    t_out_404 = datetime.strptime(f"{today_str} 16:04:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_out_404)
    assert res['allowed'] is False
    assert res['punch_type'] == 'PUNCH_OUT'
    assert res['reason'] == 'Out Time is allowed only after 4:04 PM.'

    # 6. Out Time at 04:04:01 PM (16:04:01) -> Allowed (after 4:04 PM)
    t_out_40401 = datetime.strptime(f"{today_str} 16:04:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_out_40401)
    assert res['allowed'] is True
    assert res['punch_type'] == 'PUNCH_OUT'
    assert res['reason'] is None

    # 7. Out Time at 04:30:00 PM (16:30:00) -> Allowed
    t_out_valid = datetime.strptime(f"{today_str} 16:30:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ist)
    res = validate_attendance_time_window('timerule_user', check_time=t_out_valid)
    assert res['allowed'] is True
    assert res['punch_type'] == 'PUNCH_OUT'
    assert res['reason'] is None

    # Cleanup
    delete_user('timerule_user')

def test_attendance_status_endpoint(client):
    delete_user('status_user')
    create_user('status_user', 'Status User', 'status@test.edu', '+1111111111', 'hash')

    resp = client.get('/api/webauthn/attendance/status?user_id=status_user')
    assert resp.status_code == 200
    data = resp.json
    assert data['success'] is True
    assert 'window' in data
    assert data['window']['punch_type'] == 'PUNCH_IN'
    assert 'server_datetime' in data

    delete_user('status_user')
