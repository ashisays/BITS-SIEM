<template>
  <div class="dashboard">
    <div class="dashboard-header">
      <div class="container">
        <h1>{{ currentTenant?.name || 'Tenant' }} Dashboard</h1>
        <p class="dashboard-subtitle">Security Information and Event Management</p>
      </div>
    </div>
    
    <div class="dashboard-content">
      <div class="container">
        <div class="dashboard-grid">
          <div class="dashboard-card">
            <h2>📊 Quick Stats</h2>
            <div class="stats-grid">
              <div class="stat-item">
                <span class="stat-number">{{ stats.totalEvents }}</span>
                <span class="stat-label">Total Events</span>
              </div>
              <div class="stat-item">
                <span class="stat-number">{{ stats.activeSources }}</span>
                <span class="stat-label">Active Sources</span>
              </div>
              <div class="stat-item">
                <span class="stat-number">{{ stats.alerts }}</span>
                <span class="stat-label">Alerts</span>
              </div>
              <div class="stat-item">
                <span class="stat-number">{{ stats.uptime }}</span>
                <span class="stat-label">Uptime</span>
              </div>
            </div>
          </div>
          
          <!-- Sources Section -->
          <div class="dashboard-card">
            <div class="card-header">
              <h2>🔌 Security Sources</h2>
              <div class="search-bar">
                <input 
                  v-model="searchQuery" 
                  type="text" 
                  placeholder="Search by IP address..."
                  class="search-input"
                >
              </div>
            </div>
            <div class="sources-list" v-if="filteredSources.length > 0">
              <div v-for="source in filteredSources" :key="source.id" class="source-item">
                <div class="source-info">
                  <span class="source-name">{{ source.name }}</span>
                  <span class="source-type">{{ source.type }}</span>
                </div>
                <div class="source-details">
                  <span class="source-ip">{{ source.ip }}:{{ source.port }}</span>
                  <span class="source-protocol">{{ source.protocol }}</span>
                  <span class="source-status" :class="source.status">{{ source.status }}</span>
                </div>
              </div>
            </div>
            <div v-else-if="!loading" class="empty-state">
              <p>{{ searchQuery ? 'No sources found matching your search.' : 'No sources configured yet.' }}</p>
              <router-link :to="`/tenant/${route.params.tenantId}/sources`" class="btn-primary">
                Add First Source
              </router-link>
            </div>
          </div>
          
          <!-- Reports Section -->
          <div class="dashboard-card">
            <div class="card-header">
              <h2>📋 Recent Reports</h2>
              <router-link :to="`/tenant/${route.params.tenantId}/reports`" class="view-all-link">
                View All
              </router-link>
            </div>
            <div class="reports-summary" v-if="recentReports.length > 0">
              <div v-for="report in recentReports" :key="report.id" class="report-item">
                <div class="report-info">
                  <span class="report-title">{{ report.title }}</span>
                  <span class="report-date">{{ formatDate(report.date) }}</span>
                </div>
                <div class="report-summary">{{ report.summary }}</div>
                <div class="report-stats" v-if="report.data">
                  <span v-if="report.data.total_events" class="stat-badge">
                    {{ report.data.total_events }} events
                  </span>
                  <span v-if="report.data.threats_detected" class="stat-badge threat">
                    {{ report.data.threats_detected }} threats
                  </span>
                  <span v-if="report.data.vulnerabilities" class="stat-badge warning">
                    {{ report.data.vulnerabilities }} vulnerabilities
                  </span>
                </div>
              </div>
            </div>
            <div v-else-if="!loading" class="empty-state">
              <p>No reports generated yet.</p>
            </div>
          </div>
          
          <div class="dashboard-section">
            <Notifications />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuth } from '../composables/useAuth'
import api from '../services/api'
import Notifications from '../components/Notifications.vue'

const route = useRoute()
const { user, currentTenantId } = useAuth()

const stats = ref({
  totalEvents: 0,
  activeSources: 0,
  alerts: 0,
  uptime: '0%'
})

const sources = ref([])
const reports = ref([])
const searchQuery = ref('')
const loading = ref(true)

const currentTenant = computed(() => {
  const tenantId = route.params.tenantId || currentTenantId.value
  if (!tenantId) return null
  
  // Mock tenant data - in real app this would come from API/store
  const tenants = {
    'acme-corp': { id: 'acme-corp', name: 'Acme Corporation' },
    'beta-industries': { id: 'beta-industries', name: 'Beta Industries' },
    'cisco-systems': { id: 'cisco-systems', name: 'Cisco Systems' },
    'demo-org': { id: 'demo-org', name: 'Demo Organization' },
    'bits-internal': { id: 'bits-internal', name: 'BITS Internal' }
  }
  
  return tenants[tenantId] || { id: tenantId, name: tenantId }
})

const filteredSources = computed(() => {
  if (!searchQuery.value) return sources.value
  
  return sources.value.filter(source => 
    source.ip.toLowerCase().includes(searchQuery.value.toLowerCase())
  )
})

const recentReports = computed(() => {
  return reports.value.slice(0, 3) // Show only first 3 reports
})

const loadDashboardData = async () => {
  try {
    loading.value = true
    console.log(`Loading dashboard for tenant: ${route.params.tenantId}`)
    
    // Fetch data from APIs
    const [sourcesData, notifications, reportsData, dashboardStats] = await Promise.all([
      api.getSources().catch(() => []),
      api.getNotifications().catch(() => []),
      api.getReports().catch(() => []),
      api.getDashboardStats().catch(() => ({ totalSources: 0, activeSources: 0, alerts: 0, totalEvents: 0, uptime: '0%' }))
    ])
    
    // Store data for components
    sources.value = sourcesData
    reports.value = reportsData
    
    // Use real stats from backend
    stats.value = {
      totalEvents: dashboardStats.totalEvents > 1000 ? `${(dashboardStats.totalEvents/1000).toFixed(1)}K` : dashboardStats.totalEvents.toString(),
      activeSources: dashboardStats.activeSources.toString(),
      alerts: dashboardStats.alerts.toString(),
      uptime: dashboardStats.uptime
    }
    
  } catch (error) {
    console.error('Error loading dashboard data:', error)
    // Keep default zero values for new tenants
    sources.value = []
    reports.value = []
  } finally {
    loading.value = false
  }
}

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleDateString()
}

onMounted(() => {
  loadDashboardData()
})
</script>

<style scoped>
.dashboard {
  min-height: calc(100vh - 72px);
}

@media (max-width: 768px) {
  .dashboard {
    min-height: calc(100vh - 64px);
  }
}

.dashboard-header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 60px 0;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
}

.dashboard-header h1 {
  font-size: 3rem;
  font-weight: 700;
  margin: 0 0 12px 0;
  letter-spacing: -0.025em;
}

.dashboard-subtitle {
  font-size: 1.25rem;
  opacity: 0.9;
  margin: 0;
  font-weight: 400;
}

.dashboard-content {
  padding: 48px 0;
}

@media (max-width: 768px) {
  .dashboard-header {
    padding: 40px 0;
  }
  
  .dashboard-header h1 {
    font-size: 2.25rem;
  }
  
  .dashboard-subtitle {
    font-size: 1.1rem;
  }
  
  .dashboard-content {
    padding: 32px 0;
  }
}

.dashboard-grid {
  display: grid;
  gap: 32px;
  grid-template-columns: 1fr;
  max-width: 1400px;
  margin: 0 auto;
}

.dashboard-card {
  background: white;
  border-radius: 12px;
  padding: 24px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: all 0.3s ease;
  margin-bottom: 24px;
}

.dashboard-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.card-header h2 {
  margin: 0;
  color: #333;
  font-size: 1.5rem;
}

.search-bar {
  display: flex;
  align-items: center;
}

.search-input {
  padding: 8px 16px;
  border: 2px solid #e9ecef;
  border-radius: 8px;
  font-size: 14px;
  min-width: 250px;
  transition: border-color 0.3s ease;
}

.search-input:focus {
  outline: none;
  border-color: #007bff;
}

.sources-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.source-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: #f8f9fa;
  border-radius: 8px;
  border-left: 4px solid #007bff;
  transition: all 0.3s ease;
}

.source-item:hover {
  background: #e9ecef;
  transform: translateX(4px);
}

.source-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.source-name {
  font-weight: 600;
  color: #333;
  font-size: 16px;
}

.source-type {
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.source-details {
  display: flex;
  gap: 16px;
  align-items: center;
}

.source-ip {
  font-family: 'Courier New', monospace;
  background: #e9ecef;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 14px;
}

.source-protocol {
  font-size: 12px;
  color: #666;
  text-transform: uppercase;
}

.source-status {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.source-status.active {
  background: #d4edda;
  color: #155724;
}

.source-status.warning {
  background: #fff3cd;
  color: #856404;
}

.source-status.inactive {
  background: #f8d7da;
  color: #721c24;
}

.reports-summary {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.report-item {
  padding: 16px;
  background: #f8f9fa;
  border-radius: 8px;
  border-left: 4px solid #28a745;
}

.report-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.report-title {
  font-weight: 600;
  color: #333;
  font-size: 16px;
}

.report-date {
  font-size: 12px;
  color: #666;
}

.report-summary {
  color: #555;
  margin-bottom: 12px;
  line-height: 1.4;
}

.report-stats {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.stat-badge {
  padding: 4px 12px;
  border-radius: 16px;
  font-size: 12px;
  font-weight: 600;
  background: #e9ecef;
  color: #495057;
}

.stat-badge.threat {
  background: #f8d7da;
  color: #721c24;
}

.stat-badge.warning {
  background: #fff3cd;
  color: #856404;
}

.view-all-link {
  color: #007bff;
  text-decoration: none;
  font-size: 14px;
  font-weight: 500;
  transition: color 0.3s ease;
}

.view-all-link:hover {
  color: #0056b3;
  text-decoration: underline;
}

.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: #666;
}

.empty-state p {
  margin-bottom: 16px;
}

.btn-primary {
  background: #007bff;
  color: white;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  text-decoration: none;
  font-weight: 600;
  transition: all 0.3s ease;
  display: inline-block;
}

.btn-primary:hover {
  background: #0056b3;
  transform: translateY(-1px);
}

.dashboard-card {
  background: white;
  border-radius: 16px;
  padding: 40px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  border: 1px solid #e9ecef;
  transition: all 0.2s ease;
}

.dashboard-card:hover {
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.12);
  transform: translateY(-2px);
}

.dashboard-card h2 {
  margin: 0 0 24px 0;
  color: #333;
  font-size: 1.75rem;
  font-weight: 600;
}

@media (max-width: 768px) {
  .dashboard-card {
    padding: 24px;
  }
  
  .dashboard-card h2 {
    font-size: 1.5rem;
    margin: 0 0 20px 0;
  }
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px;
}

.stat-item {
  text-align: center;
  padding: 32px 24px;
  background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
  border-radius: 12px;
  border: 1px solid #e9ecef;
  transition: all 0.2s ease;
}

.stat-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
}

.stat-number {
  display: block;
  font-size: 2.5rem;
  font-weight: 700;
  color: #667eea;
  margin-bottom: 8px;
  line-height: 1;
}

.stat-label {
  font-size: 0.875rem;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.75px;
  font-weight: 500;
}

@media (max-width: 1024px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 640px) {
  .stats-grid {
    gap: 16px;
  }
  
  .stat-item {
    padding: 24px 16px;
  }
  
  .stat-number {
    font-size: 2rem;
  }
}

.dashboard-section {
  background: white;
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  border: 1px solid #e9ecef;
}

/* Responsive Design */
@media (min-width: 768px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}

@media (min-width: 1200px) {
  .dashboard-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .dashboard-card {
    grid-column: 1 / -1;
  }
}

@media (min-width: 1600px) {
  .dashboard-grid {
    grid-template-columns: repeat(3, 1fr);
  }
  
  .dashboard-card {
    grid-column: 1 / -1;
  }
}
</style>