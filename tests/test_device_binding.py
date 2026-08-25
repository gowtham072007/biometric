import pytest
from backend.config import Config
from backend.app import create_app
from backend.models.schemas import delete_user, get_device_by_user_id, get_device_by_device_id

@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_device_binding.db"
    Config.DATABASE_PATH = str(db_file)
    
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        yield client

def test_one_user_per_device_login_flow(client):
    # Setup test users
    delete_user('user_alpha')
    delete_user('user_beta')

    # Login as admin to create users
    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})

    # Create User Alpha
    r1 = client.post('/api/admin/users', json={
        'user_id': 'user_alpha',
        'full_name': 'Alpha Student',
        'email': 'alpha@college.edu',
        'phone': '+1111111111',
        'password': 'Password@123'
    })
    assert r1.status_code == 201

    # Create User Beta
    r2 = client.post('/api/admin/users', json={
        'user_id': 'user_beta',
        'full_name': 'Beta Student',
        'email': 'beta@college.edu',
        'phone': '+2222222222',
        'password': 'Password@456'
    })
    assert r2.status_code == 201

    client.post('/api/logout')

    # Step 1: User Alpha logs in on Device A
    login_alpha = client.post('/api/login', json={
        'user_id': 'user_alpha',
        'password': 'Password@123',
        'device_id': 'device_phone_A',
        'device_name': 'Alpha iPhone 15'
    })
    assert login_alpha.status_code == 200
    assert login_alpha.json['success'] is True
    assert login_alpha.json['user']['device']['device_id'] == 'device_phone_A'
    client.post('/api/logout')

    # Step 2: User Beta attempts to log in on Device A (Same device)
    # MUST BE REJECTED - 1 User per Device Rule!
    login_beta_fail = client.post('/api/login', json={
        'user_id': 'user_beta',
        'password': 'Password@456',
        'device_id': 'device_phone_A',
        'device_name': 'Alpha iPhone 15'
    })
    assert login_beta_fail.status_code == 403
    assert login_beta_fail.json['success'] is False
    assert "already registered to user 'user_alpha'" in login_beta_fail.json['message']

    # Step 3: User Beta logs in on Device B (Their own device)
    # MUST SUCCEED
    login_beta_success = client.post('/api/login', json={
        'user_id': 'user_beta',
        'password': 'Password@456',
        'device_id': 'device_phone_B',
        'device_name': 'Beta Pixel 8'
    })
    assert login_beta_success.status_code == 200
    assert login_beta_success.json['success'] is True
    assert login_beta_success.json['user']['device']['device_id'] == 'device_phone_B'
    client.post('/api/logout')


def test_one_device_per_user_and_admin_unbind(client):
    delete_user('user_gamma')

    # Admin creates User Gamma
    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})
    client.post('/api/admin/users', json={
        'user_id': 'user_gamma',
        'full_name': 'Gamma Student',
        'email': 'gamma@college.edu',
        'phone': '+3333333333',
        'password': 'Password@789'
    })
    client.post('/api/logout')

    # User Gamma binds Device G1
    login_g1 = client.post('/api/login', json={
        'user_id': 'user_gamma',
        'password': 'Password@789',
        'device_id': 'device_gamma_1',
        'device_name': 'Gamma Galaxy S23'
    })
    assert login_g1.status_code == 200
    client.post('/api/logout')

    # User Gamma tries to log in on Device G2 (Unauthorized secondary device)
    # MUST BE REJECTED - 1 Device per User Rule!
    login_g2_fail = client.post('/api/login', json={
        'user_id': 'user_gamma',
        'password': 'Password@789',
        'device_id': 'device_gamma_2',
        'device_name': 'Gamma iPad'
    })
    assert login_g2_fail.status_code == 403
    assert "already bound to another" in login_g2_fail.json['message']

    # Admin unbinds User Gamma's device
    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})
    unbind_resp = client.post('/api/admin/users/user_gamma/unbind-device')
    assert unbind_resp.status_code == 200
    assert unbind_resp.json['success'] is True
    client.post('/api/logout')

    # Now User Gamma CAN bind Device G2
    login_g2_success = client.post('/api/login', json={
        'user_id': 'user_gamma',
        'password': 'Password@789',
        'device_id': 'device_gamma_2',
        'device_name': 'Gamma New Phone'
    })
    assert login_g2_success.status_code == 200
    assert login_g2_success.json['user']['device']['device_id'] == 'device_gamma_2'


def test_admin_device_exemption_and_management(client):
    # Admin is exempt from device lock and can login from multiple devices
    login_admin_d1 = client.post('/api/login', json={
        'user_id': 'admin',
        'password': 'Admin@123456',
        'device_id': 'admin_workstation_1'
    })
    assert login_admin_d1.status_code == 200

    login_admin_d2 = client.post('/api/login', json={
        'user_id': 'admin',
        'password': 'Admin@123456',
        'device_id': 'admin_mobile_device'
    })
    assert login_admin_d2.status_code == 200

    # Admin device listing
    devices_resp = client.get('/api/admin/devices')
    assert devices_resp.status_code == 200
    assert 'devices' in devices_resp.json


def test_webauthn_device_options_enforcement(client):
    delete_user('user_delta')

    client.post('/api/login', json={'user_id': 'admin', 'password': 'Admin@123456'})
    client.post('/api/admin/users', json={
        'user_id': 'user_delta',
        'full_name': 'Delta Student',
        'email': 'delta@college.edu',
        'phone': '+4444444444',
        'password': 'Password@Delta'
    })
    client.post('/api/logout')

    # User Delta registers device D_DELTA
    client.post('/api/login', json={
        'user_id': 'user_delta',
        'password': 'Password@Delta',
        'device_id': 'device_delta'
    })
    client.post('/api/logout')

    # WebAuthn options request with foreign device is rejected
    opt_resp = client.post('/api/webauthn/login/options', json={
        'user_id': 'user_delta',
        'device_id': 'unauthorized_foreign_device',
        'latitude': Config.DEFAULT_LATITUDE,
        'longitude': Config.DEFAULT_LONGITUDE,
        'accuracy': 10.0
    })
    assert opt_resp.status_code == 403
    assert "already bound to another" in opt_resp.json['message']
