import pytest
from backend.config import Config
from backend.app import create_app
from backend.models.schemas import delete_user, record_late_punch_in, get_user_latest_late_slip, admin_unblock_late_user, get_user_by_id

@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_late_blocking.db"
    Config.DATABASE_PATH = str(db_file)
    
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        yield client

def test_late_punch_in_blocking_and_admin_unblock_flow(client):
    delete_user('late_student')

    # Admin registers user
    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})
    client.post('/api/register', json={
        'user_id': 'late_student',
        'full_name': 'Late Student',
        'email': 'late@college.edu',
        'phone': '+1987654321',
        'password': 'StudentPassword@123'
    })
    client.post('/api/logout')

    # Simulate late punch in (e.g. 09:42:00 AM)
    slip = record_late_punch_in('late_student', '2026-08-11 09:42:00')
    assert slip is not None
    assert slip['user_id'] == 'late_student'
    assert slip['status'] == 'PENDING_APPROVAL'

    # Check user account is now blocked_late
    user = get_user_by_id('late_student')
    assert user is not None
    assert user['status'] == 'blocked_late'

    # Login as Admin to unblock user
    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})
    unblock_resp = client.post('/api/admin/users/late_student/unblock-late')
    assert unblock_resp.status_code == 200
    assert unblock_resp.json['success'] is True

    # User status should now be active
    updated_user = get_user_by_id('late_student')
    assert updated_user is not None
    assert updated_user['status'] == 'active'

    # Check late slip status is approved
    latest_slip = get_user_latest_late_slip('late_student')
    assert latest_slip is not None
    assert latest_slip['status'] == 'APPROVED'
