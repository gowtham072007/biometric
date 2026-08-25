/* ==========================================================================
   API Service Wrapper — REST Endpoints, Device Binding & Client Session
   ========================================================================== */

const API = {
  baseUrl: '/api',

  /**
   * Returns or generates a persistent unique Device ID stored in localStorage & cookie.
   */
  getDeviceId() {
    try {
      let devId = localStorage.getItem('fxec_device_id');
      if (!devId) {
        // Generate cryptographic random UUID
        if (window.crypto && window.crypto.randomUUID) {
          devId = 'dev_' + window.crypto.randomUUID().replace(/-/g, '');
        } else {
          devId = 'dev_' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
        }
        localStorage.setItem('fxec_device_id', devId);
      }
      return devId;
    } catch (e) {
      return 'dev_fallback_' + navigator.userAgent.replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
    }
  },

  /**
   * Returns a friendly device name based on user agent and platform.
   */
  getDeviceName() {
    const ua = navigator.userAgent;
    let name = 'Web Browser';
    if (/android/i.test(ua)) name = 'Android Smartphone';
    else if (/iphone/i.test(ua)) name = 'Apple iPhone';
    else if (/ipad/i.test(ua)) name = 'Apple iPad';
    else if (/macintosh|mac os x/i.test(ua)) name = 'Apple Mac';
    else if (/windows/i.test(ua)) name = 'Windows PC';
    else if (/linux/i.test(ua)) name = 'Linux Computer';
    return name;
  },

  async request(endpoint, options = {}) {
    const devId = this.getDeviceId();
    const config = {
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': devId,
        ...options.headers
      },
      credentials: 'include', // Always send HTTP-only session cookies
      ...options
    };

    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
      config.body = JSON.stringify(options.body);
    }

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, config);
      const data = await response.json().catch(() => ({ success: false, message: 'Invalid response format from server.' }));
      
      if (!response.ok) {
        throw new Error(data.message || `Request failed with status ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error(`[API Error] ${endpoint}:`, error);
      throw error;
    }
  },

  // Auth Endpoints
  registerUser(userData) {
    return this.request('/register', { method: 'POST', body: userData });
  },

  loginUser(credentials) {
    const payload = {
      ...credentials,
      device_id: this.getDeviceId(),
      device_name: this.getDeviceName()
    };
    return this.request('/login', { method: 'POST', body: payload });
  },

  loginWithGoogle(data) {
    const payload = {
      ...data,
      device_id: this.getDeviceId(),
      device_name: this.getDeviceName()
    };
    return this.request('/auth/google', { method: 'POST', body: payload });
  },

  resetPassword(data) {
    return this.request('/reset-password', { method: 'POST', body: data });
  },

  sendOtp(data) {
    return this.request('/send-otp', { method: 'POST', body: data });
  },

  verifyOtpReset(data) {
    return this.request('/verify-otp-reset', { method: 'POST', body: data });
  },

  logoutUser() {
    return this.request('/logout', { method: 'POST' });
  },

  getCurrentUser() {
    return this.request('/me', { method: 'GET' });
  },

  updateOwnProfile(profileData) {
    return this.request('/me', { method: 'PUT', body: profileData });
  },

  changeOwnPassword(current_password, new_password) {
    return this.request('/me/change-password', { method: 'POST', body: { current_password, new_password } });
  },

  getUserHistory() {
    return this.request('/user/history', { method: 'GET' });
  },

  checkAttendance(user_id) {
    return this.request(`/attendance/check/${encodeURIComponent(user_id)}`, { method: 'GET' });
  },

  // Geofence Endpoints
  getGeofenceSettings() {
    return this.request('/location/settings', { method: 'GET' });
  },

  verifyLocation(locationData) {
    return this.request('/location/verify', { method: 'POST', body: locationData });
  },

  // WebAuthn Endpoints
  getWebAuthnRegisterOptions(user_id) {
    return this.request('/webauthn/register/options', { 
      method: 'POST', 
      body: { 
        user_id,
        device_id: this.getDeviceId()
      } 
    });
  },

  verifyWebAuthnRegister(credential, credential_name, user_id) {
    return this.request('/webauthn/register/verify', { 
      method: 'POST', 
      body: { 
        credential, 
        credential_name, 
        user_id,
        device_id: this.getDeviceId(),
        device_name: credential_name || this.getDeviceName()
      } 
    });
  },

  getWebAuthnLoginOptions(user_id, locationData) {
    return this.request('/webauthn/login/options', { 
      method: 'POST', 
      body: { 
        user_id, 
        device_id: this.getDeviceId(),
        ...locationData 
      } 
    });
  },

  verifyWebAuthnLogin(credential, locationData) {
    return this.request('/webauthn/login/verify', { 
      method: 'POST', 
      body: { 
        credential, 
        device_id: this.getDeviceId(),
        ...locationData 
      } 
    });
  },

  // Admin Endpoints
  getAdminDashboard() {
    return this.request('/admin/dashboard', { method: 'GET' });
  },

  getAdminUsers(search, status, role, sort_by) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status && status !== 'all') params.append('status', status);
    if (role && role !== 'all') params.append('role', role);
    if (sort_by) params.append('sort_by', sort_by);
    return this.request(`/admin/users?${params.toString()}`, { method: 'GET' });
  },

  getAdminUserDetails(user_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}`, { method: 'GET' });
  },

  adminCreateUser(userData) {
    return this.request('/admin/users', { method: 'POST', body: userData });
  },

  updateUserStatus(user_id, status) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/status`, { method: 'POST', body: { status } });
  },

  updateUserDetails(user_id, userData) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}`, { method: 'PUT', body: userData });
  },

  adminResetUserPassword(user_id, new_password) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/reset-password`, { method: 'POST', body: { new_password } });
  },

  adminUnbindUserDevice(user_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/unbind-device`, { method: 'POST' });
  },

  adminGetDevices() {
    return this.request('/admin/devices', { method: 'GET' });
  },

  adminUnbindDeviceById(device_id) {
    return this.request(`/admin/devices/${encodeURIComponent(device_id)}`, { method: 'DELETE' });
  },

  deleteUser(user_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}`, { method: 'DELETE' });
  },

  saveGeofenceSettings(settings) {
    return this.request('/admin/geofence', { method: 'POST', body: settings });
  },

  getAdminLogs(date_filter, status, search) {
    const params = new URLSearchParams();
    if (date_filter) params.append('date_filter', date_filter);
    if (status) params.append('status', status);
    if (search) params.append('search', search);
    return this.request(`/admin/logs?${params.toString()}`, { method: 'GET' });
  },

  processAbsentees(target_date) {
    return this.request('/admin/process-absent', { method: 'POST', body: { target_date } });
  },

  // Late Slip & Unblock Endpoints
  getLatestLateSlip() {
    return this.request('/late-slip/latest', { method: 'GET' });
  },

  submitLateSlipReason(data) {
    return this.request('/late-slip/submit', { method: 'POST', body: data });
  },

  adminUnblockLateUser(user_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/unblock-late`, { method: 'POST' });
  },

  adminGetLateRequests() {
    return this.request('/admin/late-requests', { method: 'GET' });
  },

  // Credential Management Endpoints
  getUserCredentials() {
    return this.request('/webauthn/credentials', { method: 'GET' });
  },

  deleteUserCredential(credential_id) {
    return this.request(`/webauthn/credentials/${encodeURIComponent(credential_id)}`, { method: 'DELETE' });
  },

  getAdminUserCredentials(user_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/credentials`, { method: 'GET' });
  },

  adminDeleteUserCredential(user_id, credential_id) {
    return this.request(`/admin/users/${encodeURIComponent(user_id)}/credentials/${encodeURIComponent(credential_id)}`, { method: 'DELETE' });
  }
};

