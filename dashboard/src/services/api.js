const BASE_URL = 'http://localhost:8000/api'

// Helper function to make API requests with authentication
const makeRequest = async (url, options = {}) => {
  const token = localStorage.getItem('jwt')
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  }
  
  if (token) {
    headers.Authorization = `Bearer ${token}`
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
  getReports() {
    return makeRequest('/reports')
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
  getAdminUsers(tenantId = null) {
    const url = tenantId ? `/admin/users?tenantId=${tenantId}` : '/admin/users'
    return makeRequest(url)
  },
  createUser(userData) {
    return makeRequest('/admin/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    })
  }
} 