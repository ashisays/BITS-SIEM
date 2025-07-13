const BASE_URL = 'http://localhost:8000/api'

// Helper function to make API requests with authentication
const makeRequest = async (url, options = {}) => {
  const token = localStorage.getItem('jwt')
  const csrfToken = localStorage.getItem('csrf_token')
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  }
  
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  
  // Add CSRF token for state-changing operations (POST, PUT, PATCH, DELETE)
  if (csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method?.toUpperCase())) {
    headers['X-CSRF-Token'] = csrfToken
  }
  
  const response = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers,
  })
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`)
  }
  
  return response.json()
}

export default {
  register(data) {
    return makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },
  login(data) {
    return makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: data.email,
        password: data.password
      }),
    })
  },
  getSources() {
    return makeRequest('/sources')
  },
  addSource(source) {
    return makeRequest('/sources', {
      method: 'POST',
      body: JSON.stringify(source),
    })
  },
  updateSource(id, source) {
    return makeRequest(`/sources/${id}`, {
      method: 'PUT',
      body: JSON.stringify(source),
    })
  },
  deleteSource(id) {
    return makeRequest(`/sources/${id}`, {
      method: 'DELETE',
    })
  },
  getNotifications() {
    return makeRequest('/notifications')
  },
  markNotificationAsRead(notificationId) {
    return makeRequest(`/notifications/${notificationId}/read`, {
      method: 'PATCH',
    })
  },
  markAllNotificationsAsRead() {
    return makeRequest('/notifications/read-all', {
      method: 'PATCH',
    })
  },
  getReports() {
    return makeRequest('/reports')
  },
  generateReport(reportType = 'security') {
    return makeRequest('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ report_type: reportType }),
    })
  },
  getDashboardStats() {
    return makeRequest('/dashboard/stats')
  },
  
  // Admin endpoints
  getAdminTenants() {
    return makeRequest('/admin/tenants')
  },
  createTenant(tenantData) {
    return makeRequest('/admin/tenants', {
      method: 'POST',
      body: JSON.stringify(tenantData),
    })
  },
  updateTenant(tenantId, tenantData) {
    return makeRequest(`/admin/tenants/${tenantId}`, {
      method: 'PUT',
      body: JSON.stringify(tenantData),
    })
  },
  deleteTenant(tenantId) {
    return makeRequest(`/admin/tenants/${tenantId}`, {
      method: 'DELETE',
    })
  },
  updateTenantStatus(tenantId, status) {
    return makeRequest(`/admin/tenants/${tenantId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    })
  },
  getAdminUsers(tenantId = null) {
    const url = tenantId ? `/admin/users?tenantId=${tenantId}` : '/admin/users'
    return makeRequest(url)
  },
  createUser(userData) {
    return makeRequest('/admin/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    })
  },
  updateUser(userId, userData) {
    return makeRequest(`/admin/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(userData),
    })
  },
  deleteUser(userId) {
    return makeRequest(`/admin/users/${userId}`, {
      method: 'DELETE',
    })
  },
  updateUserStatus(userId, status) {
    return makeRequest(`/admin/users/${userId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    })
  }
} 