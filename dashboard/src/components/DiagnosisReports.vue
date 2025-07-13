<template>
  <div class="reports-container">
    <div class="reports-header">
      <h2>Diagnosis Reports</h2>
      <div class="reports-controls">
        <div class="filter-controls">
          <select v-model="selectedType" class="filter-select">
            <option value="">All Types</option>
            <option value="security">Security</option>
            <option value="threat">Threat</option>
            <option value="performance">Performance</option>
            <option value="compliance">Compliance</option>
          </select>
          <input 
            v-model="searchQuery" 
            type="text" 
            placeholder="Search reports..." 
            class="search-input"
          />
        </div>
        <button @click="generateReport" class="btn btn-primary">
          Generate Report
        </button>
        <button @click="refreshReports" class="btn btn-outline">
          <span class="refresh-icon">🔄</span>
        </button>
      </div>
    </div>

    <div class="reports-stats">
      <div class="stat-card">
        <span class="stat-number">{{ totalReports }}</span>
        <span class="stat-label">Total Reports</span>
      </div>
      <div class="stat-card security">
        <span class="stat-number">{{ securityCount }}</span>
        <span class="stat-label">Security</span>
      </div>
      <div class="stat-card threat">
        <span class="stat-number">{{ threatCount }}</span>
        <span class="stat-label">Threat</span>
      </div>
      <div class="stat-card recent">
        <span class="stat-number">{{ recentCount }}</span>
        <span class="stat-label">This Week</span>
      </div>
    </div>

    <div class="reports-list" v-if="filteredReports.length > 0">
      <div 
        v-for="report in paginatedReports" 
        :key="report.id" 
        class="report-card"
        :class="report.type"
        @click="viewReport(report)"
      >
        <div class="report-header">
          <div class="report-type">
            <span class="type-icon" :class="report.type">
              {{ getTypeIcon(report.type) }}
            </span>
            <span class="type-text">{{ report.type }}</span>
          </div>
          <div class="report-meta">
            <span class="report-date">{{ formatDate(report.date) }}</span>
            <span class="report-author">{{ report.generatedBy }}</span>
          </div>
        </div>
        <div class="report-content">
          <h3 class="report-title">{{ report.title }}</h3>
          <p class="report-summary">{{ report.summary }}</p>
          <div v-if="report.data" class="report-data">
            <div v-for="(value, key) in report.data" :key="key" class="data-item">
              <span class="data-key">{{ key }}:</span>
              <span class="data-value">{{ value }}</span>
            </div>
          </div>
        </div>
        <div class="report-actions">
          <button @click.stop="viewReport(report)" class="btn btn-outline btn-sm">
            View Details
          </button>
          <button @click.stop="exportReport(report)" class="btn btn-secondary btn-sm">
            Export
          </button>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <div class="empty-icon">📋</div>
      <h3>No reports found</h3>
      <p>No reports match your current filters. Generate a new report to get started.</p>
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

    <!-- Report Detail Modal -->
    <div v-if="selectedReport" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <div class="modal-header">
          <h3>{{ selectedReport.title }}</h3>
          <button @click="closeModal" class="modal-close">×</button>
        </div>
        <div class="modal-content">
          <div class="report-detail-meta">
            <div class="meta-item">
              <span class="meta-label">Type:</span>
              <span class="meta-value">{{ selectedReport.type }}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">Generated:</span>
              <span class="meta-value">{{ formatDate(selectedReport.date) }}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">By:</span>
              <span class="meta-value">{{ selectedReport.generatedBy }}</span>
            </div>
          </div>
          <div class="report-detail-summary">
            <h4>Summary</h4>
            <p>{{ selectedReport.summary }}</p>
          </div>
          <div v-if="selectedReport.data" class="report-detail-data">
            <h4>Data</h4>
            <div class="data-grid">
              <div v-for="(value, key) in selectedReport.data" :key="key" class="data-grid-item">
                <span class="data-grid-key">{{ key }}</span>
                <span class="data-grid-value">{{ value }}</span>
              </div>
            </div>
          </div>
        </div>
        <div class="modal-actions">
          <button @click="exportReport(selectedReport)" class="btn btn-primary">
            Export Report
          </button>
          <button @click="closeModal" class="btn btn-secondary">
            Close
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../services/api'

// Reactive data
const reports = ref([])
const selectedType = ref('')
const searchQuery = ref('')
const currentPage = ref(1)
const itemsPerPage = 8
const loading = ref(false)
const selectedReport = ref(null)

// Computed properties
const filteredReports = computed(() => {
  let filtered = reports.value

  if (selectedType.value) {
    filtered = filtered.filter(r => r.type === selectedType.value)
  }

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(r => 
      r.title.toLowerCase().includes(query) ||
      r.summary.toLowerCase().includes(query)
    )
  }

  return filtered.sort((a, b) => new Date(b.date) - new Date(a.date))
})

const paginatedReports = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return filteredReports.value.slice(start, end)
})

const totalPages = computed(() => {
  return Math.ceil(filteredReports.value.length / itemsPerPage)
})

const totalReports = computed(() => reports.value.length)
const securityCount = computed(() => reports.value.filter(r => r.type === 'security').length)
const threatCount = computed(() => reports.value.filter(r => r.type === 'threat').length)
const recentCount = computed(() => {
  const weekAgo = new Date()
  weekAgo.setDate(weekAgo.getDate() - 7)
  return reports.value.filter(r => new Date(r.date) >= weekAgo).length
})

// Methods
const fetchReports = async () => {
  try {
    loading.value = true
    const res = await api.getReports()
    reports.value = res.data || res
  } catch (error) {
    console.error('Error fetching reports:', error)
    // Fallback data
    reports.value = [
      {
        id: 1,
        title: "Security Summary Report",
        summary: "Weekly security overview and threat analysis",
        type: "security",
        date: new Date().toISOString().split('T')[0],
        generatedBy: "system",
        data: { total_events: 1250, threats_detected: 3, incidents_resolved: 2 }
      },
      {
        id: 2,
        title: "Threat Analysis Report",
        summary: "Analysis of recent security threats and vulnerabilities",
        type: "threat",
        date: new Date(Date.now() - 86400000).toISOString().split('T')[0],
        generatedBy: "admin",
        data: { threats_detected: 8, high_risk: 2, medium_risk: 4, low_risk: 2 }
      },
      {
        id: 3,
        title: "Performance Metrics Report",
        summary: "System performance and resource utilization analysis",
        type: "performance",
        date: new Date(Date.now() - 172800000).toISOString().split('T')[0],
        generatedBy: "system",
        data: { avg_response_time: "45ms", uptime: "99.9%", cpu_usage: "23%" }
      }
    ]
  } finally {
    loading.value = false
  }
}

const generateReport = async () => {
  try {
    const res = await api.generateReport('security')
    await fetchReports()
  } catch (error) {
    console.error('Error generating report:', error)
    alert('Failed to generate report. Please try again.')
  }
}

const refreshReports = () => {
  fetchReports()
}

const viewReport = (report) => {
  selectedReport.value = report
}

const closeModal = () => {
  selectedReport.value = null
}

const exportReport = (report) => {
  // Create a simple text export
  const content = `
Report: ${report.title}
Type: ${report.type}
Date: ${formatDate(report.date)}
Generated By: ${report.generatedBy}

Summary:
${report.summary}

Data:
${Object.entries(report.data || {}).map(([key, value]) => `${key}: ${value}`).join('\n')}
  `.trim()

  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${report.title.replace(/\s+/g, '_')}_${formatDate(report.date)}.txt`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

const getTypeIcon = (type) => {
  const icons = {
    security: '🔒',
    threat: '⚠️',
    performance: '⚡',
    compliance: '📋'
  }
  return icons[type] || '📄'
}

const formatDate = (dateString) => {
  const date = new Date(dateString)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

onMounted(() => {
  fetchReports()
})
</script>

<style scoped>
.reports-container {
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
}

.reports-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  flex-wrap: wrap;
  gap: 16px;
}

.reports-header h2 {
  margin: 0;
  color: #333;
  font-size: 24px;
  font-weight: 600;
}

.reports-controls {
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

.search-input {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  font-size: 14px;
  min-width: 200px;
}

.refresh-icon {
  font-size: 16px;
}

.reports-stats {
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

.stat-card.security {
  border-left: 4px solid #28a745;
}

.stat-card.threat {
  border-left: 4px solid #dc3545;
}

.stat-card.recent {
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

.reports-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 16px;
}

.report-card {
  background: white;
  border: 1px solid #e1e5e9;
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}

.report-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.report-card.security {
  border-left: 4px solid #28a745;
}

.report-card.threat {
  border-left: 4px solid #dc3545;
}

.report-card.performance {
  border-left: 4px solid #ffc107;
}

.report-card.compliance {
  border-left: 4px solid #17a2b8;
}

.report-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.report-type {
  display: flex;
  align-items: center;
  gap: 8px;
}

.type-icon {
  font-size: 16px;
}

.type-text {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.report-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.report-date {
  font-size: 12px;
  color: #666;
}

.report-author {
  font-size: 11px;
  color: #999;
}

.report-content {
  margin-bottom: 12px;
}

.report-title {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 16px;
  font-weight: 600;
}

.report-summary {
  margin: 0 0 8px 0;
  color: #666;
  line-height: 1.4;
  font-size: 14px;
}

.report-data {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

.data-item {
  background: #f8f9fa;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.data-key {
  font-weight: 600;
  color: #666;
}

.data-value {
  color: #333;
}

.report-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
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

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal {
  background: white;
  border-radius: 8px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid #e1e5e9;
}

.modal-header h3 {
  margin: 0;
  color: #333;
}

.modal-close {
  background: none;
  border: none;
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

.modal-content {
  padding: 20px;
}

.report-detail-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
  padding: 16px;
  background: #f8f9fa;
  border-radius: 4px;
}

.meta-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.meta-label {
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.meta-value {
  font-size: 14px;
  color: #333;
  font-weight: 500;
}

.report-detail-summary {
  margin-bottom: 20px;
}

.report-detail-summary h4 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 16px;
}

.report-detail-summary p {
  margin: 0;
  color: #666;
  line-height: 1.5;
}

.report-detail-data {
  margin-bottom: 20px;
}

.report-detail-data h4 {
  margin: 0 0 12px 0;
  color: #333;
  font-size: 16px;
}

.data-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.data-grid-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 12px;
  background: #f8f9fa;
  border-radius: 4px;
}

.data-grid-key {
  font-weight: 600;
  color: #666;
}

.data-grid-value {
  color: #333;
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  padding: 20px;
  border-top: 1px solid #e1e5e9;
}

@media (max-width: 768px) {
  .reports-container {
    padding: 16px;
  }
  
  .reports-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .reports-controls {
    justify-content: space-between;
  }
  
  .reports-stats {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .reports-list {
    grid-template-columns: 1fr;
  }
  
  .modal {
    width: 95%;
    margin: 20px;
  }
}
</style> 