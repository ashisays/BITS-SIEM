import { defineStore } from 'pinia'

export const useMainStore = defineStore('main', {
  state: () => ({
    user: null,
    tenant: null,
    notifications: [],
    jwt: localStorage.getItem('jwt') || null,
    currentTenantId: null
  }),
  getters: {
    isAuthenticated: (state) => !!state.jwt,
    isAdmin: (state) => state.user?.role === 'admin',
    currentTenant: (state) => state.tenant || state.currentTenantId
  },
  actions: {
    setUser(user) {
      this.user = user
      if (user?.tenantId) {
        this.currentTenantId = user.tenantId
      }
    },
    setTenant(tenant) {
      this.tenant = tenant
      if (tenant?.id) {
        this.currentTenantId = tenant.id
      }
    },
    setNotifications(notifications) {
      this.notifications = notifications
    },
    addNotification(notification) {
      this.notifications.unshift(notification)
    },
    setJwt(token) {
      this.jwt = token
      localStorage.setItem('jwt', token)
    },
    logout() {
      this.user = null
      this.tenant = null
      this.jwt = null
      this.currentTenantId = null
      localStorage.removeItem('jwt')
    }
  }
}) 