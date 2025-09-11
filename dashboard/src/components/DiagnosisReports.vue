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
          <div class="card-value">{{ filteredAlerts.length }}</div>
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

    <!-- Filter & Sort Controls -->
    <div class="filter-controls">
      <h3>Filter & Sort Alerts</h3>
      <div class="filter-grid">
        <!-- Severity Filter -->
        <div class="filter-group">
          <label>By Severity:</label>
          <div class="btn-group">
            <button @click="severityFilter = 'all'" :class="{ active: severityFilter === 'all' }">All</button>
            <button @click="severityFilter = 'critical'" :class="{ active: severityFilter === 'critical' }">Critical</button>
            <button @click="severityFilter = 'warning'" :class="{ active: severityFilter === 'warning' }">Warning</button>
            <button @click="severityFilter = 'info'" :class="{ active: severityFilter === 'info' }">Info</button>
          </div>
        </div>

        <!-- Date Range Filter -->
        <div class="filter-group">
          <label>By Date Range:</label>
          <div class="date-range">
            <input type="date" v-model="startDate" placeholder="Start Date">
            <span>to</span>
            <input type="date" v-model="endDate" placeholder="End Date">
          </div>
        </div>

        <!-- Sort By -->
        <div class="filter-group">
          <label>Sort By:</label>
          <select v-model="sortBy" class="sort-select">
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="severity">Severity</option>
          </select>
        </div>

        <!-- Clear Button -->
        <div class="filter-group">
          <label>&nbsp;</label>
          <button @click="clearFilters" class="clear-btn">Clear Filters</button>
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
        <button @click="exportData('filtered')" class="export-btn export-filtered" :disabled="!filteredAlerts.length">
          <i class="fas fa-filter"></i>
          Export Filtered ({{ filteredAlerts.length }})
        </button>
        <button @click="exportData('selected')" class="export-btn export-selected" :disabled="!selectedAlerts.length">
          <i class="fas fa-check-square"></i>
          Export Selected ({{ selectedAlerts.length }})
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
      
      <div v-else-if="!filteredAlerts.length" class="alerts-empty">
        <div class="empty-icon">🔍</div>
        <h4>No Security Alerts Found</h4>
        <p>No security alerts match the current filters.</p>
      </div>
      
      <div v-else class="alerts-table-container">
        <div class="alerts-table">
          <div class="alerts-header">
            <span class="col-select">
              <input type="checkbox" @change="toggleSelectAll" :checked="allVisibleSelected" title="Select all on page">
            </span>
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
          
          <div v-for="alert in paginatedAlerts" :key="alert.id" class="alerts-row" :class="{ selected: selectedAlerts.includes(alert.id) }" @click.self="openAlert(alert)" :title="'Click to view detailed information for alert #' + alert.id">
            <span class="col-select" @click.stop>
              <input type="checkbox" :value="alert.id" v-model="selectedAlerts" @click.stop>
            </span>
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
import axios from 'axios';

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
      lastUpdated: '',
      severityFilter: 'all',
      startDate: '',
      endDate: '',
      sortBy: 'newest',
      selectedAlerts: []
    };
  },
  computed: {
    filteredAlerts() {
      let filtered = [...this.alerts];

      if (this.severityFilter !== 'all') {
        if (this.severityFilter === 'warning') {
          filtered = filtered.filter(a => ['high', 'warning', 'medium'].includes(a.severity));
        } else if (this.severityFilter === 'info') {
          filtered = filtered.filter(a => ['low', 'info'].includes(a.severity));
        } else {
          filtered = filtered.filter(a => a.severity === this.severityFilter);
        }
      }

      if (this.startDate) {
        const start = new Date(this.startDate);
        start.setHours(0, 0, 0, 0);
        filtered = filtered.filter(a => new Date(a.created_at) >= start);
      }
      if (this.endDate) {
        const end = new Date(this.endDate);
        end.setHours(23, 59, 59, 999);
        filtered = filtered.filter(a => new Date(a.created_at) <= end);
      }

      const severityOrder = { critical: 4, high: 3, warning: 3, medium: 2, low: 1, info: 1 };
      filtered.sort((a, b) => {
        switch (this.sortBy) {
          case 'oldest':
            return new Date(a.created_at) - new Date(b.created_at);
          case 'severity':
            return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
          case 'newest':
          default:
            return new Date(b.created_at) - new Date(a.created_at);
        }
      });

      return filtered;
    },
    paginatedAlerts() {
      const start = (this.currentPage - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return this.filteredAlerts.slice(start, end);
    },
    totalPages() {
      return Math.ceil(this.filteredAlerts.length / this.itemsPerPage);
    },
    criticalCount() {
      return this.alerts.filter(a => a.severity === 'critical').length;
    },
    warningCount() {
      return this.alerts.filter(a => ['high', 'warning', 'medium'].includes(a.severity)).length;
    },
    infoCount() {
      return this.alerts.filter(a => ['low', 'info'].includes(a.severity)).length;
    },
    allVisibleSelected() {
      const visibleIds = this.paginatedAlerts.map(a => a.id);
      if (visibleIds.length === 0) return false;
      return visibleIds.every(id => this.selectedAlerts.includes(id));
    }
  },
  watch: {
    severityFilter() { this.currentPage = 1; },
    startDate() { this.currentPage = 1; },
    endDate() { this.currentPage = 1; },
    sortBy() { this.currentPage = 1; }
  },
  mounted() {
    this.refreshData();
  },
  beforeUnmount() {
    if (this.autoRefreshTimer) {
      clearInterval(this.autoRefreshTimer);
    }
  },
  methods: {
    async refreshData() {
      this.alertsLoading = true;
      try {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        const tenantId = user.tenantId || 'demo-org';
        const response = await axios.get(`/api/detection/alerts?tenant_id=${tenantId}&limit=1000`);
        const rawAlerts = response.data || [];
        this.alerts = this.processAndCorrelateAlerts(rawAlerts);
        this.updateLastUpdated();
      } catch (error) {
        console.error('Error loading alerts:', error);
        this.alerts = [];
      } finally {
        this.alertsLoading = false;
      }
    },
    setupAutoRefresh() {
      if (this.autoRefreshTimer) {
        clearInterval(this.autoRefreshTimer);
        this.autoRefreshTimer = null;
      }
      if (this.autoRefreshInterval > 0) {
        this.autoRefreshTimer = setInterval(() => this.refreshData(), this.autoRefreshInterval);
      }
    },
    openAlert(alert) {
      this.selectedAlert = alert;
    },
    closeAlert() {
      this.selectedAlert = null;
    },
    clearFilters() {
      this.severityFilter = 'all';
      this.startDate = '';
      this.endDate = '';
      this.sortBy = 'newest';
      this.selectedAlerts = [];
    },
    formatRefreshInterval(interval) {
      if (interval >= 60000) return `${Math.floor(interval / 60000)}min`;
      return `${Math.floor(interval / 1000)}s`;
    },
    formatDate(timestamp) {
      if (!timestamp) return 'N/A';
      return new Date(timestamp).toLocaleString();
    },
    updateLastUpdated() {
      this.lastUpdated = new Date().toLocaleString();
    },
    toggleSelectAll(event) {
      const isChecked = event.target.checked;
      const visibleIds = this.paginatedAlerts.map(a => a.id);
      if (isChecked) {
        visibleIds.forEach(id => {
          if (!this.selectedAlerts.includes(id)) {
            this.selectedAlerts.push(id);
          }
        });
      } else {
        this.selectedAlerts = this.selectedAlerts.filter(id => !visibleIds.includes(id));
      }
    },
    exportData(period) {
      try {
        let alertsToExport = [];
        let exportType = period;

        if (period === 'selected') {
          if (this.selectedAlerts.length === 0) {
            alert('No alerts selected for export.');
            return;
          }
          alertsToExport = this.alerts.filter(a => this.selectedAlerts.includes(a.id));
        } else if (period === 'filtered') {
          alertsToExport = this.filteredAlerts;
          exportType = 'filtered-report';
        } else {
          let startDate, endDate;
          const now = new Date();
          switch(period) {
            case 'today':
              startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
              endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
              break;
            case 'yesterday':
              startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
              endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
              break;
            case 'last7days':
              startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
              endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
              break;
          }
          alertsToExport = this.alerts.filter(alert => {
            const alertDate = new Date(alert.created_at);
            return alertDate >= startDate && alertDate < endDate;
          });
        }

        if (alertsToExport.length === 0) {
          alert('No alerts to export for the selected criteria.');
          return;
        }

        const csvContent = this.generateCSV(alertsToExport);
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `security-report-${exportType}-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } catch (error) {
        console.error('Error exporting reports:', error);
        alert('Failed to export reports. Please try again.');
      }
    },
    getSeverityFromConfidence(score) {
      const confidence = score * 100;
      if (confidence >= 90) return 'critical';
      if (confidence >= 70) return 'high';
      if (confidence >= 50) return 'medium';
      if (confidence >= 20) return 'low';
      return 'info';
    },

    processAndCorrelateAlerts(alerts) {
      if (!alerts || alerts.length === 0) {
        return [];
      }

      const sortedAlerts = [...alerts].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

      const correlatedAlerts = new Map();
      const fiveMinutes = 5 * 60 * 1000;

      for (const alert of sortedAlerts) {
        const correlationKey = `${alert.title}|${alert.source_ip}`;
        const existingAlert = correlatedAlerts.get(correlationKey);
        const alertTimestamp = new Date(alert.created_at).getTime();

        alert.severity = this.getSeverityFromConfidence(alert.confidence_score);

        if (existingAlert) {
          const existingTimestamp = new Date(existingAlert.created_at).getTime();
          
          if (alertTimestamp - existingTimestamp <= fiveMinutes) {
            existingAlert.created_at = alert.created_at;
            existingAlert.confidence_score = alert.confidence_score;
            existingAlert.severity = this.getSeverityFromConfidence(alert.confidence_score);
            existingAlert.correlation_count = (existingAlert.correlation_count || 1) + 1;
          } else {
            correlatedAlerts.set(correlationKey, alert);
          }
        } else {
          correlatedAlerts.set(correlationKey, alert);
        }
      }

      return Array.from(correlatedAlerts.values());
    },

    generateCSV(alerts) {
      const headers = ['ID', 'Timestamp', 'Severity', 'Type', 'Title', 'Source IP', 'Username', 'Status', 'Confidence'];
      const rows = alerts.map(alert => [
        alert.id,
        alert.created_at,
        alert.severity,
        alert.alert_type || alert.type || 'N/A',
        alert.title || alert.message || 'N/A',
        alert.source_ip || 'N/A',
        alert.username || 'N/A',
        alert.status || 'open',
        alert.confidence_score ? `${Math.round(alert.confidence_score * 100)}%` : 'N/A'
      ]);
      return [headers, ...rows].map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(',')).join('\n');
    }
  }
};
</script>

<style scoped>
.reports-container {
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
  background: #f8f9fa;
  min-height: 100vh;
}

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
  flex-wrap: wrap;
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

.export-btn:hover:not(:disabled) {
  background: #218838;
}

.export-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.export-filtered,
.export-selected {
  background-color: #17a2b8;
}

.export-filtered:hover:not(:disabled),
.export-selected:hover:not(:disabled) {
  background-color: #138496;
}

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

.alerts-loading, .alerts-empty {
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

.empty-icon {
  font-size: 48px;
  margin-bottom: 20px;
}

.alerts-empty h4 {
  margin: 0 0 10px 0;
  color: #333;
}

.alerts-table-container {
  overflow-x: auto;
}

.alerts-table {
  width: 100%;
  min-width: 1200px;
  border-collapse: collapse;
}

.alerts-header, .alerts-row {
  display: grid;
  grid-template-columns: 40px 100px 150px 120px 1fr 120px 100px 100px 80px 80px;
  border-bottom: 1px solid #eee;
}

.alerts-header {
  background: #f8f9fa;
  font-weight: 600;
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
}

.alerts-header > span, .alerts-row > span {
  padding: 12px 10px;
  display: flex;
  align-items: center;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.alerts-row {
  cursor: pointer;
  transition: background-color 0.2s;
}

.alerts-row:hover {
  background: #f8f9fa;
}

.alerts-row.selected {
  background-color: #e6f2ff;
}

.col-select input[type="checkbox"] {
  cursor: pointer;
}

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

.filter-controls {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
  margin-bottom: 30px;
}

.filter-controls h3 {
  margin: 0 0 15px 0;
  color: #333;
  font-size: 18px;
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  align-items: end;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.filter-group label {
  font-size: 14px;
  font-weight: 600;
  color: #555;
}

.btn-group {
  display: flex;
}

.btn-group button {
  padding: 8px 12px;
  border: 1px solid #ddd;
  background: #fff;
  cursor: pointer;
  transition: background-color 0.2s, color 0.2s;
  flex-grow: 1;
}

.btn-group button:first-child {
  border-top-left-radius: 4px;
  border-bottom-left-radius: 4px;
}

.btn-group button:last-child {
  border-top-right-radius: 4px;
  border-bottom-right-radius: 4px;
}

.btn-group button.active {
  background: #007bff;
  color: white;
  border-color: #007bff;
}

.date-range {
  display: flex;
  align-items: center;
  gap: 10px;
}

.date-range input[type="date"] {
  padding: 6px 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  flex-grow: 1;
}

.sort-select {
  padding: 8px 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  background: white;
  width: 100%;
}

.clear-btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  background: #6c757d;
  color: white;
  cursor: pointer;
  font-size: 14px;
  width: 100%;
}

.clear-btn:hover {
  background: #5a6268;
}

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
    min-width: 900px;
  }
}
</style>
