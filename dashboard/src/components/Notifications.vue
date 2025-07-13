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
            <option value="unread">Unread</option>
            <option value="read">Read</option>
          </select>
        </div>
        <button @click="markAllAsRead" class="btn btn-secondary" :disabled="!hasUnreadNotifications">
          Mark All as Read
        </button>
        <button @click="refreshNotifications" class="btn btn-outline">
          <span class="refresh-icon">🔄</span>
        </button>
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
        @click="markAsRead(notification)"
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
        </div>
        <div class="notification-content">
          <p class="notification-message">{{ notification.message }}</p>
          <div v-if="notification.metadata" class="notification-metadata">
            <div v-for="(value, key) in notification.metadata" :key="key" class="metadata-item">
              <span class="metadata-key">{{ key }}:</span>
              <span class="metadata-value">{{ value }}</span>
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
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useMainStore } from '../store'
import { connectWebSocket, disconnectWebSocket } from '../services/socket'
import api from '../services/api'

const store = useMainStore()

// Reactive data
const notifications = ref([])
const selectedSeverity = ref('')
const selectedStatus = ref('')
const currentPage = ref(1)
const itemsPerPage = 10
const loading = ref(false)

// Computed properties
const filteredNotifications = computed(() => {
  let filtered = notifications.value

  if (selectedSeverity.value) {
    filtered = filtered.filter(n => n.severity === selectedSeverity.value)
  }

  if (selectedStatus.value) {
    if (selectedStatus.value === 'read') {
      filtered = filtered.filter(n => n.isRead)
    } else if (selectedStatus.value === 'unread') {
      filtered = filtered.filter(n => !n.isRead)
    }
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

// Methods
const fetchNotifications = async () => {
  try {
    loading.value = true
    const res = await api.getNotifications()
    notifications.value = res.data || res
  } catch (error) {
    console.error('Error fetching notifications:', error)
    // Fallback to store notifications if API fails
    notifications.value = store.notifications
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
  if (data.type === 'notification') {
    store.addNotification(data.data)
    notifications.value.unshift(data.data)
  }
}

onMounted(() => {
  fetchNotifications()
  connectWebSocket(store.jwt, handleWebSocketMessage)
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