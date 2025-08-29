<template>
  <div class="detection-dashboard">
    <!-- Header Section -->
    <div class="dashboard-header">
      <h2 class="dashboard-title">
        <i class="fas fa-shield-alt"></i>
        Brute-Force Detection System
      </h2>
      <div class="header-actions">
        <div class="real-time-controls">
          <button @click="toggleRealTime" :class="['btn', realTimeEnabled ? 'btn-success' : 'btn-secondary']" title="Toggle real-time monitoring">
            <i class="fas" :class="realTimeEnabled ? 'fa-broadcast-tower' : 'fa-stop-circle'"></i>
            {{ realTimeEnabled ? 'Real-time ON' : 'Real-time OFF' }}
          </button>
          <div class="connection-status" :class="{ 'connected': websocketConnected, 'disconnected': !websocketConnected }">
            <i class="fas fa-circle"></i>
            {{ websocketConnected ? 'Connected' : 'Disconnected' }}
          </div>
        </div>
        <button @click="refreshData" :disabled="loading" class="btn btn-primary">
          <i class="fas fa-sync-alt" :class="{ 'fa-spin': loading }"></i>
          Refresh
        </button>
      </div>
    </div>

    <!-- Statistics Cards -->
    <div class="stats-grid">
      <div class="stat-card critical">
        <div class="stat-icon">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.active_alerts || 0 }}</h3>
          <p>Active Alerts</p>
        </div>
      </div>
      
      <div class="stat-card warning">
        <div class="stat-icon">
          <i class="fas fa-bell"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.total_alerts_24h || 0 }}</h3>
          <p>Alerts (24h)</p>
        </div>
      </div>
      
      <div class="stat-card info">
        <div class="stat-icon">
          <i class="fas fa-eye"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.total_events_24h || 0 }}</h3>
          <p>Auth Events (24h)</p>
        </div>
      </div>
      
      <div class="stat-card success">
        <div class="stat-icon">
          <i class="fas fa-check-circle"></i>
        </div>
        <div class="stat-content">
          <h3>{{ (stats.detection_accuracy * 100).toFixed(1) || 0 }}%</h3>
          <p>Detection Accuracy</p>
        </div>
      </div>
    </div>

    <!-- Security Alerts Table -->
    <div class="alerts-section">
      <div class="section-header">
        <h3>Security Alerts</h3>
        <div class="alert-filters">
          <select v-model="selectedSeverity" @change="loadAlerts" class="filter-select">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select v-model="selectedStatus" @change="loadAlerts" class="filter-select">
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      <div class="alerts-table-container">
        <table class="alerts-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Alert Type</th>
              <th>Title</th>
              <th>Username</th>
              <th>Source IP</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="alert in alerts" :key="alert.id" class="alert-row">
              <td>
                <span class="severity-badge" :class="alert.severity">
                  {{ alert.severity.toUpperCase() }}
                </span>
              </td>
              <td>
                <span class="alert-type">{{ formatAlertType(alert.alert_type) }}</span>
              </td>
              <td class="alert-title">{{ alert.title }}</td>
              <td>{{ alert.username || '-' }}</td>
              <td class="ip-cell">{{ alert.source_ip || '-' }}</td>
              <td>
                <div class="confidence-bar">
                  <div 
                    class="confidence-fill" 
                    :style="{ width: (alert.confidence_score * 100) + '%' }"
                    :class="getConfidenceClass(alert.confidence_score)"
                  ></div>
                  <span class="confidence-text">{{ (alert.confidence_score * 100).toFixed(0) }}%</span>
                </div>
              </td>
              <td>
                <select 
                  :value="alert.status" 
                  @change="updateAlertStatus(alert.id, $event.target.value)"
                  class="status-select"
                  :class="alert.status"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </td>
              <td class="date-cell">{{ formatDate(alert.created_at) }}</td>
              <td>
                <button @click="showAlertDetails(alert)" class="btn btn-sm btn-info" title="View Details">
                  <i class="fas fa-eye"></i>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        
        <div v-if="!alerts.length && !loading" class="no-alerts">
          <i class="fas fa-shield-alt"></i>
          <p>No security alerts found</p>
        </div>
        
        <div v-if="loading" class="loading-spinner">
          <i class="fas fa-spinner fa-spin"></i>
          <p>Loading alerts...</p>
        </div>
      </div>
    </div>

    <!-- Alert Details Modal -->
    <div v-if="selectedAlert" class="modal-overlay" @click="selectedAlert = null">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>Alert Details</h3>
          <button @click="selectedAlert = null" class="modal-close">
            <i class="fas fa-times"></i>
          </button>
        </div>
        
        <div class="modal-body">
          <div class="alert-detail-grid">
            <div class="detail-section">
              <h4>Basic Information</h4>
              <div class="detail-item">
                <span class="label">Alert Type:</span>
                <span class="value">{{ formatAlertType(selectedAlert.alert_type) }}</span>
              </div>
              <div class="detail-item">
                <span class="label">Severity:</span>
                <span class="value severity-badge" :class="selectedAlert.severity">
                  {{ selectedAlert.severity.toUpperCase() }}
                </span>
              </div>
              <div class="detail-item">
                <span class="label">Confidence Score:</span>
                <span class="value">{{ (selectedAlert.confidence_score * 100).toFixed(1) }}%</span>
              </div>
            </div>
            
            <div class="detail-section">
              <h4>Target Information</h4>
              <div class="detail-item">
                <span class="label">Username:</span>
                <span class="value">{{ selectedAlert.username || 'N/A' }}</span>
              </div>
              <div class="detail-item">
                <span class="label">Source IP:</span>
                <span class="value">{{ selectedAlert.source_ip || 'N/A' }}</span>
              </div>
              <div class="detail-item">
                <span class="label">Affected Systems:</span>
                <span class="value">{{ selectedAlert.affected_systems?.join(', ') || 'N/A' }}</span>
              </div>
            </div>
          </div>
          
          <div class="detail-section">
            <h4>Description</h4>
            <p class="alert-description">{{ selectedAlert.description }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { useAuth } from '../composables/useAuth'
import { connectWebSocket, disconnectWebSocket, isConnected } from '../services/socket'

export default {
  name: 'DetectionDashboard',
  setup() {
    const { user, tenantId } = useAuth()
    return { user, tenantId }
  },
  data() {
    return {
      loading: false,
      websocketConnected: false,
      realTimeEnabled: true,
      stats: {
        total_events_24h: 0,
        total_alerts_24h: 0,
        active_alerts: 0,
        top_source_ips: [],
        alert_severity_breakdown: {},
        detection_accuracy: 0
      },
      alerts: [],
      selectedAlert: null,
      selectedSeverity: '',
      selectedStatus: '',
      notificationSettings: {
        soundEnabled: true,
        desktopNotifications: true,
        autoRefresh: true
      }
    }
  },
  async mounted() {
    await this.loadData()
    
    // Set up auto-refresh every 30 seconds
    this.refreshInterval = setInterval(() => {
      if (this.notificationSettings.autoRefresh) {
        this.loadData()
      }
    }, 30000)
    
    // Initialize WebSocket connection for real-time notifications
    this.initializeWebSocket()
    
    // Request notification permissions
    this.requestNotificationPermissions()
  },
  beforeUnmount() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval)
    }
    
    // Disconnect WebSocket
    if (this.websocketConnected) {
      disconnectWebSocket()
    }
  },
  methods: {
    async loadData() {
      await Promise.all([
        this.loadStats(),
        this.loadAlerts()
      ])
    },
    
    initializeWebSocket() {
      if (!this.tenantId) {
        console.warn('No tenant ID available for WebSocket connection')
        return
      }
      
      const token = localStorage.getItem('token')
      if (!token) {
        console.warn('No authentication token available for WebSocket connection')
        return
      }
      
      try {
        connectWebSocket(
          token,
          this.tenantId,
          this.handleWebSocketMessage,
          this.handleWebSocketConnect,
          this.handleWebSocketDisconnect
        )
      } catch (error) {
        console.error('Failed to initialize WebSocket:', error)
      }
    },
    
    handleWebSocketMessage(data) {
      console.log('Received real-time update:', data)
      
      if (data.type === 'security_alert') {
        // Handle security alert notification
        this.handleSecurityAlert(data)
        
        // Show desktop notification if enabled
        if (this.notificationSettings.desktopNotifications) {
          this.showDesktopNotification(data)
        }
        
        // Play sound if enabled
        if (this.notificationSettings.soundEnabled) {
          this.playAlertSound()
        }
      }
    },
    
    handleWebSocketConnect(event) {
      console.log('WebSocket connected')
      this.websocketConnected = true
      
      // Show connection status
      this.$nextTick(() => {
        this.showToast('Real-time monitoring connected', 'success')
      })
    },
    
    handleWebSocketDisconnect(event) {
      console.log('WebSocket disconnected')
      this.websocketConnected = false
      
      // Show disconnection status
      this.$nextTick(() => {
        this.showToast('Real-time monitoring disconnected', 'warning')
      })
    },
    
    handleSecurityAlert(alert) {
      // Add new alert to the top of the list
      const newAlert = {
        id: alert.alert_id || `new_${Date.now()}`,
        alert_type: alert.type,
        severity: alert.severity,
        title: alert.title,
        description: alert.message,
        username: alert.metadata?.username || 'Unknown',
        source_ip: alert.source_ip,
        confidence_score: alert.metadata?.confidence_score || 0.8,
        status: 'open',
        created_at: alert.created_at || new Date().toISOString(),
        affected_systems: alert.metadata?.affected_systems || []
      }
      
      // Add to alerts list
      this.alerts.unshift(newAlert)
      
      // Keep only last 100 alerts
      if (this.alerts.length > 100) {
        this.alerts = this.alerts.slice(0, 100)
      }
      
      // Update stats
      this.stats.total_alerts_24h += 1
      this.stats.active_alerts += 1
      
      // Update severity breakdown
      const severity = newAlert.severity.toLowerCase()
      this.stats.alert_severity_breakdown[severity] = (this.stats.alert_severity_breakdown[severity] || 0) + 1
      
      // Show toast notification
      this.showToast(`New ${alert.severity} alert: ${alert.title}`, 'info')
    },
    
    async requestNotificationPermissions() {
      if ('Notification' in window && Notification.permission === 'default') {
        try {
          const permission = await Notification.requestPermission()
          if (permission === 'granted') {
            console.log('Desktop notifications enabled')
          }
        } catch (error) {
          console.warn('Failed to request notification permissions:', error)
        }
      }
    },
    
    showDesktopNotification(alert) {
      if ('Notification' in window && Notification.permission === 'granted') {
        const notification = new Notification('Security Alert', {
          body: alert.message,
          icon: '/favicon.ico',
          tag: alert.id,
          requireInteraction: true
        })
        
        // Handle notification click
        notification.onclick = () => {
          window.focus()
          notification.close()
        }
      }
    },
    
    playAlertSound() {
      try {
        // Create audio context for alert sound
        const audioContext = new (window.AudioContext || window.webkitAudioContext)()
        const oscillator = audioContext.createOscillator()
        const gainNode = audioContext.createGain()
        
        oscillator.connect(gainNode)
        gainNode.connect(audioContext.destination)
        
        // Configure alert sound
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime)
        oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1)
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime + 0.2)
        
        gainNode.gain.setValueAtTime(0.1, audioContext.currentTime)
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3)
        
        oscillator.start(audioContext.currentTime)
        oscillator.stop(audioContext.currentTime + 0.3)
        
      } catch (error) {
        console.warn('Failed to play alert sound:', error)
      }
    },
    
    showToast(message, type = 'info') {
      // Create toast element
      const toast = document.createElement('div')
      toast.className = `toast toast-${type}`
      toast.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${this.getToastColor(type)};
        color: white;
        padding: 12px 16px;
        border-radius: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        z-index: 9999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
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
    },
    
    getToastColor(type) {
      switch (type) {
        case 'success': return '#28a745'
        case 'warning': return '#ffc107'
        case 'error': return '#dc3545'
        case 'info': return '#17a2b8'
        default: return '#6c757d'
      }
    },
    
    toggleRealTime() {
      this.realTimeEnabled = !this.realTimeEnabled
      
      if (this.realTimeEnabled) {
        this.initializeWebSocket()
        this.showToast('Real-time monitoring enabled', 'success')
      } else {
        if (this.websocketConnected) {
          disconnectWebSocket()
        }
        this.showToast('Real-time monitoring disabled', 'warning')
      }
    },
    
    async loadStats() {
      try {
        const response = await fetch(`/api/detection/stats?tenant_id=${this.tenantId}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        })
        
        if (response.ok) {
          this.stats = await response.json()
        }
      } catch (error) {
        console.error('Error loading detection stats:', error)
      }
    },
    
    async loadAlerts() {
      try {
        this.loading = true
        const params = new URLSearchParams({
          tenant_id: this.tenantId,
          limit: '50'
        })
        
        if (this.selectedSeverity) params.append('severity', this.selectedSeverity)
        if (this.selectedStatus) params.append('status', this.selectedStatus)
        
        const response = await fetch(`/api/detection/alerts?${params}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        })
        
        if (response.ok) {
          this.alerts = await response.json()
        }
      } catch (error) {
        console.error('Error loading alerts:', error)
      } finally {
        this.loading = false
      }
    },
    
    async updateAlertStatus(alertId, newStatus) {
      try {
        const response = await fetch(`/api/detection/alerts/${alertId}/status?tenant_id=${this.tenantId}&status=${newStatus}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        })
        
        if (response.ok) {
          // Update local alert status
          const alert = this.alerts.find(a => a.id === alertId)
          if (alert) {
            alert.status = newStatus
          }
          // Reload stats to update counts
          await this.loadStats()
          
          this.showToast(`Alert status updated to ${newStatus}`, 'success')
        }
      } catch (error) {
        console.error('Error updating alert status:', error)
        this.showToast('Failed to update alert status', 'error')
      }
    },
    
    async refreshData() {
      await this.loadData()
      this.showToast('Data refreshed', 'info')
    },
    
    showAlertDetails(alert) {
      this.selectedAlert = alert
    },
    
    formatAlertType(type) {
      return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    },
    
    formatDate(dateString) {
      return new Date(dateString).toLocaleString()
    },
    
    getConfidenceClass(score) {
      if (score >= 0.8) return 'high'
      if (score >= 0.6) return 'medium'
      return 'low'
    }
  }
}
</script>

<style scoped>
.detection-dashboard {
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 2px solid #e9ecef;
}

.dashboard-title {
  font-size: 2rem;
  font-weight: 600;
  color: #2c3e50;
  margin: 0;
}

.dashboard-title i {
  color: #3498db;
  margin-right: 10px;
}

.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.real-time-controls {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-right: 15px;
}

.connection-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.connection-status.connected {
  color: #28a745;
}

.connection-status.disconnected {
  color: #dc3545;
}

.connection-status i {
  font-size: 0.75rem;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 0.875rem;
}

.btn-info {
  background: #17a2b8;
  color: white;
}

/* Statistics Cards */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: white;
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  gap: 15px;
  border-left: 4px solid;
}

.stat-card.critical {
  border-left-color: #e74c3c;
}

.stat-card.warning {
  border-left-color: #f39c12;
}

.stat-card.info {
  border-left-color: #3498db;
}

.stat-card.success {
  border-left-color: #27ae60;
}

.stat-icon {
  font-size: 2rem;
  opacity: 0.8;
}

.stat-content h3 {
  font-size: 2rem;
  font-weight: 700;
  margin: 0;
  color: #2c3e50;
}

.stat-content p {
  margin: 5px 0 0 0;
  color: #7f8c8d;
  font-weight: 500;
}

/* Alerts Section */
.alerts-section {
  background: white;
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  margin-bottom: 30px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.section-header h3 {
  margin: 0;
  color: #2c3e50;
  font-weight: 600;
}

.alert-filters {
  display: flex;
  gap: 10px;
}

.filter-select {
  padding: 6px 12px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  background: white;
}

.alerts-table-container {
  overflow-x: auto;
}

.alerts-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 10px;
}

.alerts-table th,
.alerts-table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #e9ecef;
}

.alerts-table th {
  background: #f8f9fa;
  font-weight: 600;
  color: #495057;
}

.severity-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.critical {
  background: #e74c3c;
  color: white;
}

.severity-badge.high {
  background: #f39c12;
  color: white;
}

.severity-badge.medium {
  background: #3498db;
  color: white;
}

.severity-badge.low {
  background: #27ae60;
  color: white;
}

.confidence-bar {
  position: relative;
  width: 80px;
  height: 20px;
  background: #e9ecef;
  border-radius: 10px;
  overflow: hidden;
}

.confidence-fill {
  height: 100%;
  border-radius: 10px;
  transition: width 0.3s;
}

.confidence-fill.high {
  background: #27ae60;
}

.confidence-fill.medium {
  background: #f39c12;
}

.confidence-fill.low {
  background: #e74c3c;
}

.confidence-text {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-size: 0.75rem;
  font-weight: 600;
  color: #2c3e50;
}

.status-select {
  padding: 4px 8px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  font-size: 0.875rem;
}

.status-select.open {
  background: #fee;
  color: #e74c3c;
}

.status-select.investigating {
  background: #fff3cd;
  color: #f39c12;
}

.status-select.resolved {
  background: #d4edda;
  color: #27ae60;
}

.status-select.false_positive {
  background: #f8f9fa;
  color: #6c757d;
}

.no-alerts, .loading-spinner {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.no-alerts i, .loading-spinner i {
  font-size: 3rem;
  margin-bottom: 15px;
  opacity: 0.5;
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 12px;
  max-width: 800px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid #e9ecef;
}

.modal-header h3 {
  margin: 0;
  color: #2c3e50;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: #6c757d;
}

.modal-body {
  padding: 20px;
}

.alert-detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.detail-section h4 {
  margin: 0 0 15px 0;
  color: #2c3e50;
  font-weight: 600;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
  padding-bottom: 8px;
  border-bottom: 1px solid #f8f9fa;
}

.detail-item .label {
  font-weight: 500;
  color: #6c757d;
}

.detail-item .value {
  font-weight: 600;
  color: #2c3e50;
}

.alert-description {
  background: #f8f9fa;
  padding: 15px;
  border-radius: 6px;
  margin: 0;
  line-height: 1.6;
}
</style>
