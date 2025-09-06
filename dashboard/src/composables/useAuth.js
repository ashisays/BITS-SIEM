import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'

// Global auth state
const isAuthenticated = ref(false)
const user = ref(null)
const currentTenantId = ref(null)
const csrfToken = ref(null)

// Initialize auth state from localStorage
const initializeAuth = () => {
  const token = localStorage.getItem('jwt')
  const userStr = localStorage.getItem('user')
  const tenantId = localStorage.getItem('currentTenantId')
  const storedCsrfToken = localStorage.getItem('csrf_token')
  
  if (token && userStr) {
    try {
      isAuthenticated.value = true
      user.value = JSON.parse(userStr)
      currentTenantId.value = tenantId
      csrfToken.value = storedCsrfToken
    } catch (error) {
      console.error('Error parsing user data:', error)
      clearAuth()
    }
  } else {
    clearAuth()
  }
}

// Clear auth state
const clearAuth = () => {
  isAuthenticated.value = false
  user.value = null
  currentTenantId.value = null
  csrfToken.value = null
  localStorage.removeItem('jwt')
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  localStorage.removeItem('currentTenantId')
  localStorage.removeItem('csrf_token')
}

// Set auth state
const setAuth = (token, userData, tenantId = null, csrf = null) => {
  localStorage.setItem('jwt', token)
  localStorage.setItem('token', token) // Also store as 'token' for compatibility
  localStorage.setItem('user', JSON.stringify(userData))
  
  if (tenantId) {
    localStorage.setItem('currentTenantId', tenantId)
    currentTenantId.value = tenantId
  }
  
  if (csrf) {
    localStorage.setItem('csrf_token', csrf)
    csrfToken.value = csrf
  }
  
  isAuthenticated.value = true
  user.value = userData
}

// Get CSRF token
const getCsrfToken = () => {
  return csrfToken.value || localStorage.getItem('csrf_token')
}

// Update current tenant
const setCurrentTenant = (tenantId) => {
  currentTenantId.value = tenantId
  localStorage.setItem('currentTenantId', tenantId)
}

// Check if user has access to tenant
const hasAccessToTenant = (tenantId) => {
  if (!user.value) return false
  
  // Superadmin has access to all tenants
  if (user.value.role === 'superadmin') {
    return true
  }
  
  // Admin has access to their own tenant
  if (user.value.role === 'admin' && user.value.tenantId === tenantId) {
    return true
  }
  
  // Check if user belongs to this tenant
  return user.value.tenantId === tenantId || 
         user.value.tenants?.includes(tenantId) ||
         user.value.accessibleTenants?.includes(tenantId)
}

// Check if user is admin
const isAdmin = computed(() => {
  return user.value?.role === 'admin' || user.value?.roles?.includes('admin')
})

// Check if user is superadmin
const isSuperAdmin = computed(() => {
  return user.value?.role === 'superadmin'
})

// Get user's accessible tenants
const getUserTenants = () => {
  if (!user.value) return []
  
  // For superadmin users, return all tenants (this would come from API in real app)
  if (isSuperAdmin.value) {
    return [
      { id: 'acme-corp', name: 'Acme Corporation' },
      { id: 'beta-industries', name: 'Beta Industries' },
      { id: 'cisco-systems', name: 'Cisco Systems' },
      { id: 'demo-org', name: 'Demo Organization' },
      { id: 'bits-internal', name: 'BITS Internal' }
    ]
  }
  
  // For regular users, return their assigned tenants
  return user.value.tenants || [
    { id: user.value.tenantId, name: user.value.tenantName || user.value.tenantId }
  ]
}

// Session timeout handling
let sessionTimer = null
const SESSION_TIMEOUT = 30 * 60 * 1000 // 30 minutes

const resetSessionTimer = () => {
  if (sessionTimer) clearTimeout(sessionTimer)
  
  if (isAuthenticated.value) {
    sessionTimer = setTimeout(() => {
      console.warn('Session expired')
      logout()
    }, SESSION_TIMEOUT)
  }
}

// Logout function
const logout = () => {
  clearAuth()
  if (sessionTimer) clearTimeout(sessionTimer)
  
  // Redirect to login using window.location for compatibility
  window.location.href = '/login'
}

// Activity tracking for session management
const trackActivity = () => {
  if (isAuthenticated.value) {
    resetSessionTimer()
    // Update last activity timestamp
    localStorage.setItem('lastActivity', Date.now().toString())
  }
}

// Check for session expiry on page load
const checkSessionExpiry = () => {
  const lastActivity = localStorage.getItem('lastActivity')
  if (lastActivity) {
    const elapsed = Date.now() - parseInt(lastActivity)
    if (elapsed > SESSION_TIMEOUT) {
      console.warn('Session expired due to inactivity')
      clearAuth()
      return false
    }
  }
  return true
}

// Watch for auth changes to manage session timer
watch(isAuthenticated, (newValue) => {
  if (newValue) {
    resetSessionTimer()
  } else {
    if (sessionTimer) clearTimeout(sessionTimer)
  }
})

// Track user activity
if (typeof window !== 'undefined') {
  const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart']
  activityEvents.forEach(event => {
    document.addEventListener(event, trackActivity, { passive: true })
  })
}

// Main composable function
export function useAuth() {
  // Initialize on first use
  if (!isAuthenticated.value && !user.value) {
    initializeAuth()
    checkSessionExpiry()
  }
  
  return {
    // State
    isAuthenticated: computed(() => isAuthenticated.value),
    user: computed(() => user.value),
    currentTenantId: computed(() => currentTenantId.value),
    csrfToken: computed(() => csrfToken.value),
    isAdmin,
    isSuperAdmin,
    
    // Methods
    setAuth,
    clearAuth,
    logout,
    setCurrentTenant,
    hasAccessToTenant,
    getUserTenants,
    getCsrfToken,
    initializeAuth,
    checkSessionExpiry,
    trackActivity,
    resetSessionTimer
  }
}
