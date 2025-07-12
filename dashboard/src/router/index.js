import { createRouter, createWebHistory } from 'vue-router'
import Login from '../components/Login.vue'
import Register from '../components/Register.vue'
import Dashboard from '../views/Dashboard.vue'
import SourceConfig from '../components/SourceConfig.vue'
import Notifications from '../components/Notifications.vue'
import DiagnosisReports from '../components/DiagnosisReports.vue'

const routes = [
  // Public routes
  { 
    path: '/', 
    redirect: '/login' 
  },
  { 
    path: '/login', 
    name: 'Login',
    component: Login 
  },
  { 
    path: '/register', 
    name: 'Register',
    component: Register 
  },
  
  // Tenant-specific routes
  {
    path: '/tenant/:tenantId',
    name: 'TenantBase',
    redirect: to => `/tenant/${to.params.tenantId}/dashboard`,
    meta: { requiresAuth: true, requiresTenant: true }
  },
  {
    path: '/tenant/:tenantId/dashboard',
    name: 'TenantDashboard',
    component: Dashboard,
    meta: { requiresAuth: true, requiresTenant: true }
  },
  {
    path: '/tenant/:tenantId/sources',
    name: 'TenantSources',
    component: SourceConfig,
    meta: { requiresAuth: true, requiresTenant: true }
  },
  {
    path: '/tenant/:tenantId/notifications',
    name: 'TenantNotifications', 
    component: Notifications,
    meta: { requiresAuth: true, requiresTenant: true }
  },
  {
    path: '/tenant/:tenantId/reports',
    name: 'TenantReports',
    component: DiagnosisReports,
    meta: { requiresAuth: true, requiresTenant: true }
  },
  
  // Legacy routes for backward compatibility (redirect to tenant-specific)
  { 
    path: '/dashboard', 
    redirect: to => {
      const tenantId = getCurrentTenantId()
      return tenantId ? `/tenant/${tenantId}/dashboard` : '/login'
    },
    meta: { requiresAuth: true }
  },
  { 
    path: '/sources', 
    redirect: to => {
      const tenantId = getCurrentTenantId()
      return tenantId ? `/tenant/${tenantId}/sources` : '/login'
    },
    meta: { requiresAuth: true }
  },
  { 
    path: '/notifications', 
    redirect: to => {
      const tenantId = getCurrentTenantId()
      return tenantId ? `/tenant/${tenantId}/notifications` : '/login'
    },
    meta: { requiresAuth: true }
  },
  { 
    path: '/reports', 
    redirect: to => {
      const tenantId = getCurrentTenantId()
      return tenantId ? `/tenant/${tenantId}/reports` : '/login'
    },
    meta: { requiresAuth: true }
  },
  
  // Admin routes for multi-tenant management
  {
    path: '/admin',
    name: 'Admin',
    redirect: '/admin/tenants',
    meta: { requiresAuth: true, requiresAdmin: true }
  },
  {
    path: '/admin/tenants',
    name: 'AdminTenants',
    component: () => import('../components/AdminTenants.vue'),
    meta: { requiresAuth: true, requiresAdmin: true }
  },
  {
    path: '/admin/users',
    name: 'AdminUsers', 
    component: () => import('../components/AdminUsers.vue'),
    meta: { requiresAuth: true, requiresAdmin: true }
  },
  
  // Catch-all route
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    redirect: '/login'
  }
]

// Helper function to get current tenant ID from user context
function getCurrentTenantId() {
  try {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      const user = JSON.parse(userStr)
      return user.tenantId || user.defaultTenantId
    }
  } catch (e) {
    console.error('Error getting tenant ID:', e)
  }
  return null
}

// Helper function to check if user has admin privileges
function isAdmin() {
  try {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      const user = JSON.parse(userStr)
      return user.role === 'admin' || user.roles?.includes('admin')
    }
  } catch (e) {
    console.error('Error checking admin status:', e)
  }
  return false
}

// Helper function to check if user has access to tenant
function hasAccessToTenant(tenantId) {
  try {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      const user = JSON.parse(userStr)
      // Admin has access to all tenants
      if (isAdmin()) return true
      // Check if user belongs to this tenant
      return user.tenantId === tenantId || 
             user.tenants?.includes(tenantId) ||
             user.accessibleTenants?.includes(tenantId)
    }
  } catch (e) {
    console.error('Error checking tenant access:', e)
  }
  return false
}

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Enhanced navigation guard with multitenancy support
router.beforeEach((to, from, next) => {
  const isAuthenticated = !!localStorage.getItem('jwt')
  const { requiresAuth, requiresTenant, requiresAdmin } = to.meta
  
  // Check authentication
  if (requiresAuth && !isAuthenticated) {
    next('/login')
    return
  }
  
  // Check admin access
  if (requiresAdmin && !isAdmin()) {
    console.warn('Access denied: Admin privileges required')
    const tenantId = getCurrentTenantId()
    next(tenantId ? `/tenant/${tenantId}/dashboard` : '/login')
    return
  }
  
  // Check tenant access
  if (requiresTenant && to.params.tenantId) {
    if (!hasAccessToTenant(to.params.tenantId)) {
      console.warn(`Access denied to tenant: ${to.params.tenantId}`)
      const userTenantId = getCurrentTenantId()
      next(userTenantId ? `/tenant/${userTenantId}/dashboard` : '/login')
      return
    }
  }
  
  // Set current tenant in store/context if accessing tenant route
  if (to.params.tenantId) {
    // You can dispatch to Vuex store or set in composable here
    // store.dispatch('setCurrentTenant', to.params.tenantId)
    localStorage.setItem('currentTenantId', to.params.tenantId)
  }
  
  next()
})

// Add route helper methods to router instance
router.getTenantRoute = (routeName, tenantId = null) => {
  const currentTenantId = tenantId || getCurrentTenantId()
  if (!currentTenantId) return null
  
  const routeMap = {
    'dashboard': `/tenant/${currentTenantId}/dashboard`,
    'sources': `/tenant/${currentTenantId}/sources`,
    'notifications': `/tenant/${currentTenantId}/notifications`,
    'reports': `/tenant/${currentTenantId}/reports`
  }
  
  return routeMap[routeName] || `/tenant/${currentTenantId}/dashboard`
}

router.navigateToTenant = (routeName, tenantId = null) => {
  const route = router.getTenantRoute(routeName, tenantId)
  if (route) {
    router.push(route)
  }
}

export default router 