<template>
  <div class="reports-container">
    <!-- Header -->
    <div class="reports-header">
      <div class="header-left">
        <h1 class="reports-title">
          <i class="fas fa-shield-alt"></i>
          Security Reports
        </h1>
        <p class="reports-subtitle">Real-time security alerts and analysis from database</p>
      </div>
      <div class="header-right">
        <div class="last-updated">
          <i class="fas fa-clock"></i>
          Last updated: {{ lastUpdated }}
        </div>
        <div class="refresh-controls">
          <button @click="refreshData" :disabled="alertsLoading" class="refresh-btn">
            <i class="fas fa-sync-alt" :class="{ 'spinning': alertsLoading }"></i>
            {{ alertsLoading ? 'Refreshing...' : 'Refresh' }}
          </button>
          <select v-model="autoRefreshInterval" @change="setupAutoRefresh" class="refresh-select">
            <option value="0">Auto-refresh: Off</option>
            <option value="30000">Auto-refresh: 30s</option>
            <option value="60000">Auto-refresh: 1min</option>
            <option value="300000">Auto-refresh: 5min</option>
            <option value="600000">Auto-refresh: 10min</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="summary-cards">
      <div class="summary-card total">
        <div class="card-icon">
          <i class="fas fa-list-ul"></i>
        </div>
        <div class="card-content">
          <div class="card-value">{{ alerts.length }}</div>
          <div class="card-label">Total Alerts</div>
        </div>
      </div>
      <div class="summary-card critical">
        <div class="card-icon">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="card-content">
          <div class="card-value">{{ criticalCount }}</div>
          <div class="card-label">Critical</div>
        </div>
      </div>
      <div class="summary-card warning">
        <div class="card-icon">
          <i class="fas fa-exclamation-circle"></i>
        </div>
        <div class="card-content">
          <div class="card-value">{{ warningCount }}</div>
          <div class="card-label">High/Warning</div>
        </div>
      </div>
      <div class="summary-card info">
        <div class="card-icon">
          <i class="fas fa-info-circle"></i>
        </div>
        <div class="card-content">
          <div class="card-value">{{ infoCount }}</div>
          <div class="card-label">Medium/Low</div>
        </div>
      </div>
    </div>

    <!-- Export Controls -->
    <div class="export-controls">
      <h3>Export Security Reports</h3>
      <div class="export-buttons">
        <button @click="exportData('today')" class="export-btn">
          <i class="fas fa-download"></i>
          Today
        </button>
        <button @click="exportData('yesterday')" class="export-btn">
          <i class="fas fa-download"></i>
          Yesterday
        </button>
        <button @click="exportData('last7days')" class="export-btn">
          <i class="fas fa-download"></i>
          Last 7 Days
        </button>
      </div>
    </div>

    <!-- Alerts Table -->
    <div class="alerts-section">
      <div class="section-header">
        <h3>Security Alerts</h3>
        <div class="alerts-meta">
          <span>{{ filteredAlerts.length }} alerts found</span>
          <span v-if="autoRefreshInterval > 0" class="auto-refresh-status">
            <i class="fas fa-sync-alt spinning"></i>
            Auto-refreshing every {{ formatRefreshInterval(autoRefreshInterval) }}
          </span>
        </div>
      </div>
      
      <div v-if="alertsLoading" class="alerts-loading">
        <div class="loading-spinner"></div>
        <span>Loading security alerts...</span>
      </div>
      
      <div v-else-if="!alerts.length" class="alerts-empty">
        <div class="empty-icon">🔍</div>
        <h4>No Security Alerts Found</h4>
        <p>No security alerts are currently available. This could mean:</p>
        <ul>
          <li>No security events have been detected</li>
          <li>Database connection issues</li>
          <li>Tenant has no alert permissions</li>
        </ul>
      </div>
      
      <div v-else class="alerts-table-container">
        <div class="alerts-table">
          <div class="alerts-header">
            <span class="col-severity">Severity</span>
            <span class="col-timestamp">Timestamp</span>
            <span class="col-type">Alert Type</span>
            <span class="col-title">Title</span>
            <span class="col-ip">Source IP</span>
            <span class="col-username">Username</span>
            <span class="col-confidence">Confidence</span>
            <span class="col-status">Status</span>
            <span class="col-actions">Actions</span>
          </div>
          
          <div v-for="alert in paginatedAlerts" :key="alert.id" class="alerts-row" @click="openAlert(alert)" :title="'Click to view detailed information for alert #' + alert.id">
            <span class="col-severity">
              <span class="severity-badge" :class="alert.severity">{{ alert.severity.toUpperCase() }}</span>
            </span>
            <span class="col-timestamp">{{ formatDate(alert.created_at) }}</span>
            <span class="col-type">{{ alert.alert_type }}</span>
            <span class="col-title" :title="alert.description">{{ alert.title }}</span>
            <span class="col-ip">{{ alert.source_ip || 'N/A' }}</span>
            <span class="col-username">{{ alert.username || 'N/A' }}</span>
            <span class="col-confidence">
              <div class="confidence-bar">
                <div class="confidence-fill" :style="{ width: Math.round((alert.confidence_score || 0) * 100) + '%' }"></div>
                <span class="confidence-text">{{ Math.round((alert.confidence_score || 0) * 100) }}%</span>
              </div>
            </span>
            <span class="col-status">
              <span class="status-badge" :class="alert.status">{{ alert.status }}</span>
            </span>
            <span class="col-actions" @click.stop>
              <button @click="openAlert(alert)" class="action-btn details" title="View Details">
                <i class="fas fa-eye"></i>
              </button>
            </span>
          </div>
        </div>
        
        <!-- Pagination -->
        <div v-if="totalPages > 1" class="alerts-pagination">
          <button @click="currentPage--" :disabled="currentPage === 1" class="pagination-btn">Previous</button>
          <span class="pagination-info">
            Page {{ currentPage }} of {{ totalPages }} 
            (showing {{ (currentPage - 1) * itemsPerPage + 1 }}-{{ Math.min(currentPage * itemsPerPage, filteredAlerts.length) }} of {{ filteredAlerts.length }} alerts)
          </span>
          <button @click="currentPage++" :disabled="currentPage === totalPages" class="pagination-btn">Next</button>
        </div>
      </div>
    </div>

    <!-- Alert Details Modal -->
    <div v-if="selectedAlert" class="modal-overlay" @click="closeAlert">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>Alert Details</h3>
          <button @click="closeAlert" class="modal-close">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body">
          <div class="alert-details">
            <div class="detail-group">
              <div class="detail-row">
                <strong>Alert ID:</strong> {{ selectedAlert.id }}
              </div>
              <div class="detail-row">
                <strong>Title:</strong> {{ selectedAlert.title }}
              </div>
              <div class="detail-row">
                <strong>Alert Type:</strong> {{ selectedAlert.alert_type }}
              </div>
              <div class="detail-row">
                <strong>Severity:</strong> 
                <span class="severity-badge" :class="selectedAlert.severity">{{ selectedAlert.severity.toUpperCase() }}</span>
              </div>
              <div class="detail-row">
                <strong>Status:</strong> 
                <span class="status-badge" :class="selectedAlert.status">{{ selectedAlert.status }}</span>
              </div>
              <div class="detail-row">
                <strong>Confidence Score:</strong> {{ Math.round((selectedAlert.confidence_score || 0) * 100) }}%
              </div>
              <div class="detail-row">
                <strong>Source IP:</strong> {{ selectedAlert.source_ip || 'N/A' }}
              </div>
              <div class="detail-row">
                <strong>Username:</strong> {{ selectedAlert.username || 'N/A' }}
              </div>
              <div class="detail-row">
                <strong>Created:</strong> {{ formatDate(selectedAlert.created_at) }}
              </div>
              <div class="detail-row" v-if="selectedAlert.description">
                <strong>Description:</strong>
                <p class="description-text">{{ selectedAlert.description }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'DiagnosisReports',
  data() {
    return {
      alertsLoading: false,
      alerts: [],
      selectedAlert: null,
      currentPage: 1,
      itemsPerPage: 20,
      autoRefreshInterval: 0,
      autoRefreshTimer: null,
      lastUpdated: ''
    }
  },
  computed: {
    filteredAlerts() {
      return this.alerts
    },
    paginatedAlerts() {
      const start = (this.currentPage - 1) * this.itemsPerPage
      const end = start + this.itemsPerPage
      return this.filteredAlerts.slice(start, end)
    },
    totalPages() {
      return Math.ceil(this.filteredAlerts.length / this.itemsPerPage)
    },
    criticalCount() {
      return this.alerts.filter(a => a.severity === 'critical').length
    },
    warningCount() {
      return this.alerts.filter(a => ['high', 'warning', 'medium'].includes(a.severity)).length
    },
    infoCount() {
      return this.alerts.filter(a => ['low', 'info'].includes(a.severity)).length
    }
  },
  mounted() {
    this.refreshData()
  },
  beforeUnmount() {
    if (this.autoRefreshTimer) {
      clearInterval(this.autoRefreshTimer)
    }
  },
  methods: {
    async refreshData() {
      this.alertsLoading = true
      try {
        const user = JSON.parse(localStorage.getItem('user') || '{}')
        const tenantId = user.tenantId || 'demo-org'
        
        // Try to fetch from detection API first, fallback to main API
        let response
        try {
          response = await axios.get(`/api/detection/alerts?tenant_id=${tenantId}&limit=1000`)
        } catch (error) {
          console.warn('Detection API not available, using main API')
          response = await axios.get('/api/notifications')
        }
        
        this.alerts = response.data || []
        this.updateLastUpdated()
      } catch (error) {
        console.error('Error loading alerts:', error)
        this.alerts = []
      } finally {
        this.alertsLoading = false
      }
    },
    setupAutoRefresh() {
      if (this.autoRefreshTimer) {
        clearInterval(this.autoRefreshTimer)
        this.autoRefreshTimer = null
      }
      
      if (this.autoRefreshInterval > 0) {
        this.autoRefreshTimer = setInterval(() => {
          this.refreshData()
        }, this.autoRefreshInterval)
      }
    },
    openAlert(alert) {
      this.selectedAlert = alert
    },
    closeAlert() {
      this.selectedAlert = null
    },
    formatRefreshInterval(interval) {
      if (interval >= 60000) {
        return Math.floor(interval / 60000) + 'min'
      }
      return Math.floor(interval / 1000) + 's'
    },
    async exportData(period) {
      try {
        let startDate, endDate
        const now = new Date()
        
        switch(period) {
          case 'today':
            startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate())
            endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
            break
          case 'yesterday':
            startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1)
            endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate())
            break
          case 'last7days':
            startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7)
            endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
            break
        }
        
        const filteredAlerts = this.alerts.filter(alert => {
          const alertDate = new Date(alert.created_at)
          return alertDate >= startDate && alertDate < endDate
        })
        
        const csvContent = this.generateCSV(filteredAlerts)
        const blob = new Blob([csvContent], { type: 'text/csv' })
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `security-report-${period}-${new Date().toISOString().split('T')[0]}.csv`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
      } catch (error) {
        console.error('Error exporting reports:', error)
        alert('Failed to export reports. Please try again.')
      }
    },
    generateCSV(alerts) {
      const headers = ['ID', 'Timestamp', 'Severity', 'Type', 'Title', 'Source IP', 'Username', 'Status', 'Confidence']
      const rows = alerts.map(alert => [
        alert.id,
        alert.created_at,
        alert.severity,
        alert.alert_type || alert.type || 'N/A',
        alert.title || alert.message || 'N/A',
        alert.source_ip || 'N/A',
        alert.username || 'N/A',
        alert.status || 'open',
        alert.confidence_score ? Math.round(alert.confidence_score * 100) + '%' : 'N/A'
      ])
      
      return [headers, ...rows]
        .map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
        .join('\n')
    },
    getSeverityIcon(severity) {
      const icons = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        warning: '🟡',
        low: '🔵',
        info: '🔵'
      }
      return icons[severity] || '⚪'
    },
    formatTimestamp(timestamp) {
      if (!timestamp) return 'N/A'
      return new Date(timestamp).toLocaleTimeString()
    },
    formatDate(timestamp) {
      if (!timestamp) return 'N/A'
      return new Date(timestamp).toLocaleString()
    },
    updateLastUpdated() {
      this.lastUpdated = new Date().toLocaleString()
    }
  }
}
</script>

<style scoped>
/* Container and Layout */
.reports-container {
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
  background: #f8f9fa;
  min-height: 100vh;
}

/* Header */
.reports-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
}

.reports-title {
  margin: 0;
  color: #333;
  font-size: 28px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.reports-title i {
  color: #007bff;
}

.reports-subtitle {
  margin: 5px 0 0 0;
  color: #666;
  font-size: 14px;
}

.header-right {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 10px;
}

.last-updated {
  font-size: 12px;
  color: #666;
  display: flex;
  align-items: center;
  gap: 5px;
}

.refresh-controls {
  display: flex;
  align-items: center;
  gap: 10px;
}

.refresh-btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  background: #007bff;
  color: white;
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 5px;
}

.refresh-btn:hover:not(:disabled) {
  background: #0056b3;
}

.refresh-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.refresh-select {
  padding: 6px 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 12px;
  background: white;
}

.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Summary Cards */
.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.summary-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
  display: flex;
  align-items: center;
  gap: 15px;
}

.summary-card.total {
  border-left: 4px solid #007bff;
}

.summary-card.critical {
  border-left: 4px solid #dc3545;
}

.summary-card.warning {
  border-left: 4px solid #ffc107;
}

.summary-card.info {
  border-left: 4px solid #28a745;
}

.card-icon {
  font-size: 24px;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: #f8f9fa;
}

.card-content {
  flex: 1;
}

.card-value {
  font-size: 32px;
  font-weight: bold;
  margin: 0;
  color: #333;
}

.card-label {
  font-size: 14px;
  color: #666;
  margin: 0;
}

/* Export Controls */
.export-controls {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
  margin-bottom: 30px;
}

.export-controls h3 {
  margin: 0 0 15px 0;
  color: #333;
  font-size: 18px;
}

.export-buttons {
  display: flex;
  gap: 10px;
}

.export-btn {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  background: #28a745;
  color: white;
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.export-btn:hover {
  background: #218838;
}

/* Alerts Section */
.alerts-section {
  background: white;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
  overflow: hidden;
}

.section-header {
  padding: 20px;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-header h3 {
  margin: 0;
  color: #333;
  font-size: 20px;
}

.alerts-meta {
  display: flex;
  align-items: center;
  gap: 20px;
  font-size: 14px;
  color: #666;
}

.auto-refresh-status {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #28a745;
}

/* Loading and Empty States */
.alerts-loading {
  padding: 60px 20px;
  text-align: center;
  color: #666;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 15px;
}

.alerts-empty {
  padding: 60px 20px;
  text-align: center;
  color: #666;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 20px;
}

.alerts-empty h4 {
  margin: 0 0 10px 0;
  color: #333;
}

.alerts-empty ul {
  text-align: left;
  display: inline-block;
  margin: 15px 0;
}

/* Alerts Table */
.alerts-table-container {
  overflow-x: auto;
}

.alerts-table {
  width: 100%;
  border-collapse: collapse;
}

.alerts-header {
  display: grid;
  grid-template-columns: 100px 150px 120px 1fr 120px 100px 100px 80px 80px;
  background: #f8f9fa;
  font-weight: 600;
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
  border-bottom: 2px solid #dee2e6;
}

.alerts-header > span {
  padding: 15px 10px;
  border-right: 1px solid #dee2e6;
}

.alerts-row {
  display: grid;
  grid-template-columns: 100px 150px 120px 1fr 120px 100px 100px 80px 80px;
  border-bottom: 1px solid #eee;
  cursor: pointer;
  transition: background-color 0.2s;
}

.alerts-row:hover {
  background: #f8f9fa;
}

.alerts-row > span {
  padding: 12px 10px;
  border-right: 1px solid #eee;
  display: flex;
  align-items: center;
  font-size: 13px;
}

.col-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Badges */
.severity-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  color: white;
}

.severity-badge.critical {
  background: #dc3545;
}

.severity-badge.high {
  background: #fd7e14;
}

.severity-badge.medium,
.severity-badge.warning {
  background: #ffc107;
  color: #212529;
}

.severity-badge.low,
.severity-badge.info {
  background: #28a745;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.status-badge.open {
  background: #fef3cd;
  color: #856404;
}

.status-badge.resolved {
  background: #d1e7dd;
  color: #0f5132;
}

.status-badge.investigating {
  background: #cff4fc;
  color: #055160;
}

/* Confidence Bar */
.confidence-bar {
  position: relative;
  width: 60px;
  height: 16px;
  background: #e9ecef;
  border-radius: 8px;
  overflow: hidden;
}

.confidence-fill {
  height: 100%;
  background: linear-gradient(90deg, #dc3545 0%, #ffc107 50%, #28a745 100%);
  transition: width 0.3s ease;
}

.confidence-text {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 600;
  color: #333;
}

/* Action Buttons */
.action-btn {
  padding: 6px 8px;
  border: none;
  border-radius: 4px;
  background: #007bff;
  color: white;
  cursor: pointer;
  font-size: 12px;
}

.action-btn:hover {
  background: #0056b3;
}

/* Pagination */
.alerts-pagination {
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-top: 1px solid #eee;
}

.pagination-btn {
  padding: 8px 16px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  cursor: pointer;
  font-size: 14px;
}

.pagination-btn:hover:not(:disabled) {
  background: #f8f9fa;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.pagination-info {
  font-size: 14px;
  color: #666;
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 8px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow: hidden;
  box-shadow: 0 4px 20px rgba(0,0,0,0.2);
}

.modal-header {
  padding: 20px;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-header h3 {
  margin: 0;
  color: #333;
}

.modal-close {
  border: none;
  background: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #333;
}

.modal-body {
  padding: 20px;
  max-height: 60vh;
  overflow-y: auto;
}

.detail-group {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.detail-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.detail-row strong {
  min-width: 140px;
  color: #333;
  font-weight: 600;
}

.description-text {
  margin: 5px 0 0 0;
  line-height: 1.5;
  color: #666;
}

/* Responsive */
@media (max-width: 768px) {
  .reports-header {
    flex-direction: column;
    align-items: stretch;
    gap: 20px;
  }
  
  .summary-cards {
    grid-template-columns: 1fr;
  }
  
  .export-buttons {
    flex-wrap: wrap;
  }
  
  .alerts-table {
    font-size: 12px;
  }
  
  .alerts-table th,
  .alerts-table td {
    padding: 8px;
  }
}
</style>
