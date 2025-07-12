import { defineStore } from 'pinia'

export const useMainStore = defineStore('main', {
  state: () => ({
    user: null,
    tenant: null,
    notifications: [],
    jwt: localStorage.getItem('jwt') || null
  }),
  actions: {
    setUser(user) {
      this.user = user
    },
    setTenant(tenant) {
      this.tenant = tenant
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
      localStorage.removeItem('jwt')
    }
  }
}) 