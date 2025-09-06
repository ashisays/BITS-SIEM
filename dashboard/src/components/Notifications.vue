<template>
  <div class="notifications-container">
    <div class="notifications-header">
      <h2>Notifications</h2>
      <div class="notifications-controls">
        <div class="filter-controls">
          <select v-model="selectedSeverity" class="filter-select">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>
          <select v-model="selectedStatus" class="filter-select">
            <option value="">All Status</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="suppressed">Suppressed</option>
            <option value="safe">Safe</option>
          </select>
          <select v-model="selectedType" class="filter-select">
            <option value="">All Types</option>
            <option value="security_alert">Security Alerts</option>
            <option value="system_notification">System Notifications</option>
          </select>
        </div>
        <div class="action-controls">
          <button @click="markAllAsRead" class="btn btn-secondary" :disabled="!hasUnreadNotifications">
            Mark All as Read
          </button>
          <button v-if="isAdmin" @click="refreshNotifications" class="btn btn-outline">
            <span class="refresh-icon">🔄</span>
          </button>
        </div>
      </div>
    </div>

    <div class="notifications-stats">
      <div class="stat-card">
        <span class="stat-number">{{ totalNotifications }}</span>
        <span class="stat-label">Total</span>
      </div>
      <div class="stat-card critical">
        <span class="stat-number">{{ criticalCount }}</span>
        <span class="stat-label">Critical</span>
      </div>
      <div class="stat-card warning">
        <span class="stat-number">{{ warningCount }}</span>
        <span class="stat-label">Warning</span>
      </div>
      <div class="stat-card unread">
        <span class="stat-number">{{ unreadCount }}</span>
        <span class="stat-label">Unread</span>
      </div>
    </div>

    <div class="notifications-list" v-if="filteredNotifications.length > 0">
      <div 
        v-for="notification in paginatedNotifications" 
        :key="notification.id" 
        class="notification-card"
        :class="[notification.severity, { unread: !notification.isRead }]"
      >
        <div class="notification-header">
          <div class="notification-severity">
            <span class="severity-icon" :class="notification.severity">
              {{ getSeverityIcon(notification.severity) }}
            </span>
            <span class="severity-text">{{ notification.severity }}</span>
          </div>
          <div class="notification-meta">
            <span class="notification-time">{{ formatTime(notification.timestamp) }}</span>
            <span v-if="!notification.isRead" class="unread-indicator">●</span>
          </div>
          <div class="notification-actions">
            <button 
              v-if="!notification.isRead" 
              @click.stop="markAsRead(notification)" 
              class="action-btn mark-read"
              title="Mark as Read"
            >
              ✓
            </button>
            <button 
              v-if="notification.type === 'security_alert' && notification.status === 'open'" 
              @click.stop="investigateNotification(notification)" 
              class="action-btn investigate"
              title="Mark as Investigating"
            >
              🔍
            </button>
            <button 
              v-if="notification.type === 'security_alert' && notification.status === 'open'" 
              @click.stop="resolveNotification(notification)" 
              class="action-btn resolve"
              title="Mark as Resolved"
            >
              ✅
            </button>
            <button 
              v-if="notification.type === 'security_alert' && isAdmin" 
              @click.stop="suppressNotification(notification)" 
              class="action-btn suppress"
              title="Suppress Alert (Admin Only)"
            >
              🔇
            </button>
            <button 
              v-if="notification.type === 'security_alert' && notification.status === 'open'" 
              @click.stop="markAsSafe(notification)" 
              class="action-btn mark-safe"
              title="Mark as Safe"
            >
              🛡️
            </button>
            <button 
              v-if="isAdmin || notification.type === 'system_notification'" 
              @click.stop="deleteNotification(notification)" 
              class="action-btn delete"
              title="Delete"
            >
              🗑️
            </button>
          </div>
        </div>
        <div class="notification-content" @click="markAsRead(notification)">
          <p class="notification-message">{{ notification.message }}</p>
          <div v-if="notification.metadata" class="notification-metadata">
            <div v-for="(value, key) in notification.metadata" :key="key" class="metadata-item">
              <span class="metadata-key">{{ key }}:</span>
              <span class="metadata-value">{{ formatMetadataValue(value) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <div class="empty-icon">🔔</div>
      <h3>No notifications found</h3>
      <p>You're all caught up! No notifications match your current filters.</p>
    </div>

    <!-- Pagination -->
    <div v-if="totalPages > 1" class="pagination">
      <button 
        @click="currentPage--" 
        :disabled="currentPage === 1"
        class="pagination-btn"
      >
        Previous
      </button>
      <span class="pagination-info">
        Page {{ currentPage }} of {{ totalPages }}
      </span>
      <button 
        @click="currentPage++" 
        :disabled="currentPage === totalPages"
        class="pagination-btn"
      >
        Next
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useMainStore } from '../store'
import { useAuth } from '../composables/useAuth'
import { connectWebSocket, disconnectWebSocket } from '../services/socket'
import api from '../services/api'

const store = useMainStore()
const { isAuthenticated, user, currentTenantId } = useAuth()

// Reactive data
const notifications = ref([])
const selectedSeverity = ref('')
const selectedStatus = ref('')
const selectedType = ref('')
const currentPage = ref(1)
const itemsPerPage = 10
const loading = ref(false)

// Watch for authentication changes
watch(() => isAuthenticated.value, (newAuthState) => {
  console.log('🔐 Authentication state changed:', newAuthState)
  if (newAuthState) {
    console.log('✅ User authenticated, fetching notifications...')
    fetchNotifications()
  } else {
    console.log('❌ User not authenticated, clearing notifications')
    notifications.value = []
  }
}, { immediate: true })

// Computed properties
const filteredNotifications = computed(() => {
  let filtered = notifications.value

  if (selectedSeverity.value) {
    filtered = filtered.filter(n => n.severity === selectedSeverity.value)
  }

  if (selectedStatus.value) {
    filtered = filtered.filter(n => n.status === selectedStatus.value)
  }

  if (selectedType.value) {
    filtered = filtered.filter(n => n.type === selectedType.value)
  }

  return filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
})

const paginatedNotifications = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return filteredNotifications.value.slice(start, end)
})

const totalPages = computed(() => {
  return Math.ceil(filteredNotifications.value.length / itemsPerPage)
})

const totalNotifications = computed(() => notifications.value.length)
const criticalCount = computed(() => notifications.value.filter(n => n.severity === 'critical').length)
const warningCount = computed(() => notifications.value.filter(n => n.severity === 'warning').length)
const unreadCount = computed(() => notifications.value.filter(n => !n.isRead).length)
const hasUnreadNotifications = computed(() => unreadCount.value > 0)
const isAdmin = computed(() => user.value?.role === 'admin')

// Methods
const fetchNotifications = async () => {
  try {
    loading.value = true
    console.log('🔍 Fetching notifications...')
    console.log('🔑 Auth state:', { isAuthenticated: isAuthenticated.value, user: user.value, tenantId: currentTenantId.value })
    
    const res = await api.getNotifications()
    console.log('📧 Notifications API response:', res)
    
    // Handle both array and object responses
    if (Array.isArray(res)) {
      notifications.value = res
    } else if (res && res.data && Array.isArray(res.data)) {
      notifications.value = res.data
    } else if (res && Array.isArray(res)) {
      notifications.value = res
    } else {
      console.warn('⚠️ Unexpected notifications response format:', res)
      notifications.value = []
    }
    
    console.log(`✅ Loaded ${notifications.value.length} notifications`)
    
    // Log some details for debugging
    if (notifications.value.length > 0) {
      const criticalCount = notifications.value.filter(n => n.severity === 'critical').length
      const securityCount = notifications.value.filter(n => n.type === 'security_alert').length
      console.log(`📊 Critical alerts: ${criticalCount}, Security alerts: ${securityCount}`)
    }
    
  } catch (error) {
    console.error('❌ Error fetching notifications:', error)
    // Fallback to store notifications if API fails
    notifications.value = store.notifications || []
  } finally {
    loading.value = false
  }
}

const markAsRead = async (notification) => {
  if (notification.isRead) return
  
  try {
    // Update locally first for immediate feedback
    notification.isRead = true
    
    // Call API to mark notification as read
    await api.markNotificationAsRead(notification.id)
  } catch (error) {
    console.error('Error marking notification as read:', error)
    // Revert on error
    notification.isRead = false
  }
}

const markAllAsRead = async () => {
  try {
    // Call API to mark all notifications as read
    await api.markAllNotificationsAsRead()
    // Update locally after successful API call
    notifications.value.forEach(n => n.isRead = true)
  } catch (error) {
    console.error('Error marking all notifications as read:', error)
  }
}

const markAsSafe = async (notification) => {
  try {
    // Update locally first for immediate feedback
    notification.status = 'safe'
    notification.isRead = true
    
    // Call API to mark notification as safe
    await api.updateNotificationStatus(notification.id, 'safe')
    
    showToast(`Alert marked as safe: ${notification.message.substring(0, 50)}...`, 'success')
  } catch (error) {
    console.error('Error marking notification as safe:', error)
    // Revert on error
    notification.status = 'open'
    notification.isRead = false
  }
}

const investigateNotification = async (notification) => {
  try {
    // Update locally first for immediate feedback
    notification.status = 'investigating'
    
    // Call API to mark notification as investigating
    await api.investigateNotification(notification.id)
    
    showToast(`Alert marked as investigating: ${notification.message.substring(0, 50)}...`, 'info')
  } catch (error) {
    console.error('Error marking notification as investigating:', error)
    // Revert on error
    notification.status = 'open'
  }
}

const resolveNotification = async (notification) => {
  try {
    // Update locally first for immediate feedback
    notification.status = 'resolved'
    notification.isRead = true
    
    // Call API to mark notification as resolved
    await api.resolveNotification(notification.id)
    
    showToast(`Alert marked as resolved: ${notification.message.substring(0, 50)}...`, 'success')
  } catch (error) {
    console.error('Error marking notification as resolved:', error)
    // Revert on error
    notification.status = 'open'
    notification.isRead = false
  }
}

const suppressNotification = async (notification) => {
  try {
    // Update locally first for immediate feedback
    notification.status = 'suppressed'
    notification.isRead = true
    
    // Call API to suppress notification
    await api.suppressNotification(notification.id)
    
    showToast(`Alert suppressed: ${notification.message.substring(0, 50)}...`, 'warning')
  } catch (error) {
    console.error('Error suppressing notification:', error)
    // Revert on error
    notification.status = 'open'
    notification.isRead = false
  }
}

const deleteNotification = async (notification) => {
  if (!confirm('Are you sure you want to delete this notification?')) {
    return
  }
  
  try {
    // Remove from local list first for immediate feedback
    const index = notifications.value.findIndex(n => n.id === notification.id)
    if (index > -1) {
      notifications.value.splice(index, 1)
    }
    
    // Call API to delete notification
    await api.deleteNotification(notification.id)
    
    showToast('Notification deleted successfully', 'success')
  } catch (error) {
    console.error('Error deleting notification:', error)
    // Revert on error by refetching
    await fetchNotifications()
  }
}

const formatMetadataValue = (value) => {
  if (typeof value === 'object' && value !== null) {
    return JSON.stringify(value, null, 2)
  }
  return value
}

const refreshNotifications = () => {
  fetchNotifications()
}

const getSeverityIcon = (severity) => {
  const icons = {
    critical: '🚨',
    warning: '⚠️',
    info: 'ℹ️'
  }
  return icons[severity] || '📢'
}

const formatTime = (timestamp) => {
  const date = new Date(timestamp)
  const now = new Date()
  const diff = now - date
  
  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return date.toLocaleDateString()
}

// WebSocket connection for real-time notifications
const handleWebSocketMessage = (data) => {
  console.log('Received WebSocket notification:', data)
  
  // Handle security alerts
  if (data.type === 'security_alert') {
    const notification = {
      id: data.id || `notification_${Date.now()}`,
      message: data.message || data.title,
      severity: data.severity || 'info',
      timestamp: data.created_at || new Date().toISOString(),
      isRead: false,
      metadata: data.metadata || {}
    }
    
    // Add to notifications list
    notifications.value.unshift(notification)
    store.addNotification(notification)
    
    // Show toast notification
    showToast(`New ${data.severity} alert: ${data.title}`, 'info')
  }
  
  // Handle other notification types
  if (data.type === 'notification') {
    store.addNotification(data.data)
    notifications.value.unshift(data.data)
  }
}

// Show toast notification
const showToast = (message, type = 'info') => {
  const toast = document.createElement('div')
  toast.className = `toast toast-${type}`
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${getToastColor(type)};
    color: white;
    padding: 12px 16px;
    border-radius: 6px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    z-index: 9999;
    max-width: 300px;
    animation: slideInRight 0.3s ease-out;
  `
  
  toast.textContent = message
  document.body.appendChild(toast)
  
  // Auto-remove after 4 seconds
  setTimeout(() => {
    if (toast.parentElement) {
      toast.style.animation = 'slideOutRight 0.3s ease-in'
      setTimeout(() => {
        if (toast.parentElement) {
          toast.remove()
        }
      }, 300)
    }
  }, 4000)
}

const getToastColor = (type) => {
  switch (type) {
    case 'success': return '#28a745'
    case 'warning': return '#ffc107'
    case 'error': return '#dc3545'
    case 'info': return '#17a2b8'
    default: return '#6c757d'
  }
}

onMounted(() => {
  console.log('🚀 Notifications component mounted')
  console.log('🔑 Initial auth state:', { 
    isAuthenticated: isAuthenticated.value, 
    user: user.value, 
    tenantId: currentTenantId.value 
  })
  
  // Check localStorage directly for debugging
  const storedToken = localStorage.getItem('jwt') || localStorage.getItem('token')
  const storedUser = localStorage.getItem('user')
  const storedTenant = localStorage.getItem('currentTenantId')
  
  console.log('📦 Stored data:', { storedToken: !!storedToken, storedUser: !!storedUser, storedTenant })
  
  // Force fetch notifications after a short delay to ensure auth state is ready
  setTimeout(() => {
    console.log('⏰ Delayed fetch attempt...')
    console.log('🔑 Delayed auth state:', { 
      isAuthenticated: isAuthenticated.value, 
      user: user.value, 
      tenantId: currentTenantId.value 
    })
    
    if (isAuthenticated.value && user.value && currentTenantId.value) {
      console.log('✅ User authenticated, fetching notifications...')
      fetchNotifications()
    } else if (storedToken && storedUser) {
      console.log('🔄 Using stored auth data to fetch notifications...')
      // Try to fetch with stored data
      fetchNotifications()
    } else {
      console.warn('⚠️ Still no authentication data available')
    }
  }, 200)
  
  // Connect to WebSocket for real-time notifications
  const token = storedToken
  const tenantId = currentTenantId.value || user.value?.tenantId || storedTenant || 'demo-org'
  
  console.log('🔌 Connecting WebSocket for tenant:', tenantId)
  
  if (token && tenantId) {
    connectWebSocket(token, tenantId, handleWebSocketMessage)
  } else {
    console.warn('⚠️ Missing token or tenantId for WebSocket connection')
  }
})

onUnmounted(() => {
  disconnectWebSocket()
})
</script>

<style scoped>
.notifications-container {
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
}

.notifications-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  flex-wrap: wrap;
  gap: 16px;
}

.notifications-header h2 {
  margin: 0;
  color: #333;
  font-size: 24px;
  font-weight: 600;
}

.notifications-controls {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}

.filter-controls {
  display: flex;
  gap: 8px;
}

.filter-select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  font-size: 14px;
}

.refresh-icon {
  font-size: 16px;
}

.notifications-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: white;
  padding: 16px;
  border-radius: 8px;
  border: 1px solid #e1e5e9;
  text-align: center;
  transition: all 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-card.critical {
  border-left: 4px solid #dc3545;
}

.stat-card.warning {
  border-left: 4px solid #ffc107;
}

.stat-card.unread {
  border-left: 4px solid #007bff;
}

.stat-number {
  display: block;
  font-size: 24px;
  font-weight: bold;
  color: #333;
}

.stat-label {
  display: block;
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.notifications-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.notification-card {
  background: white;
  border: 1px solid #e1e5e9;
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}

.notification-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.notification-card.unread {
  border-left: 4px solid #007bff;
  background: #f8f9ff;
}

.notification-card.critical {
  border-left: 4px solid #dc3545;
}

.notification-card.warning {
  border-left: 4px solid #ffc107;
}

.notification-card.info {
  border-left: 4px solid #17a2b8;
}

.notification-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.notification-severity {
  display: flex;
  align-items: center;
  gap: 8px;
}

.severity-icon {
  font-size: 16px;
}

.severity-text {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.notification-meta {
  display: flex;
  align-items: center;
  gap: 8px;
}

.notification-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}

.action-btn {
  background: none;
  border: none;
  padding: 4px 6px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s ease;
  opacity: 0.7;
}

.action-btn:hover {
  opacity: 1;
  transform: scale(1.1);
}

.action-btn.mark-read {
  color: #28a745;
}

.action-btn.mark-read:hover {
  background: #d4edda;
}

.action-btn.mark-safe {
  color: #17a2b8;
}

.action-btn.mark-safe:hover {
  background: #d1ecf1;
}

.action-btn.delete {
  color: #dc3545;
}

.action-btn.delete:hover {
  background: #f8d7da;
}

.action-btn.investigate {
  color: #17a2b8;
}

.action-btn.investigate:hover {
  background: #d1ecf1;
}

.action-btn.resolve {
  color: #28a745;
}

.action-btn.resolve:hover {
  background: #d4edda;
}

.action-btn.suppress {
  color: #6c757d;
}

.action-btn.suppress:hover {
  background: #e2e3e5;
}

.notification-time {
  font-size: 12px;
  color: #666;
}

.unread-indicator {
  color: #007bff;
  font-size: 12px;
}

.notification-content {
  margin-top: 8px;
}

.notification-message {
  margin: 0 0 8px 0;
  color: #333;
  line-height: 1.5;
}

.notification-metadata {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

.metadata-item {
  background: #f8f9fa;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.metadata-key {
  font-weight: 600;
  color: #666;
}

.metadata-value {
  color: #333;
}

.empty-state {
  text-align: center;
  padding: 48px 24px;
  color: #666;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
  opacity: 0.5;
}

.empty-state h3 {
  margin: 0 0 8px 0;
  color: #333;
}

.empty-state p {
  margin: 0;
  font-size: 14px;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 16px;
  margin-top: 24px;
  padding: 16px;
}

.pagination-btn {
  padding: 8px 16px;
  border: 1px solid #ddd;
  background: white;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.pagination-btn:hover:not(:disabled) {
  background: #f8f9fa;
  border-color: #007bff;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.pagination-info {
  font-size: 14px;
  color: #666;
}

.action-controls {
  display: flex;
  gap: 8px;
  align-items: center;
}

@media (max-width: 768px) {
  .notifications-container {
    padding: 16px;
  }
  
  .notifications-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .notifications-controls {
    justify-content: space-between;
  }
  
  .notifications-stats {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style> 