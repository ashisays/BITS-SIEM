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
          
          <div class="dashboard-section">
            <SourceConfig />
          </div>
          
          <div class="dashboard-section">
            <Notifications />
          </div>
          
          <div class="dashboard-section">
            <DiagnosisReports />
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
import SourceConfig from '../components/SourceConfig.vue'
import Notifications from '../components/Notifications.vue'
import DiagnosisReports from '../components/DiagnosisReports.vue'

const route = useRoute()
const { user, currentTenantId } = useAuth()

const stats = ref({
  totalEvents: '12.4K',
  activeSources: '8',
  alerts: '3',
  uptime: '99.9%'
})

const currentTenant = computed(() => {
  const tenantId = route.params.tenantId || currentTenantId.value
  if (!tenantId) return null
  
  // Mock tenant data - in real app this would come from API/store
  const tenants = {
    'acme-corp': { id: 'acme-corp', name: 'Acme Corporation' },
    'beta-industries': { id: 'beta-industries', name: 'Beta Industries' }
  }
  
  return tenants[tenantId] || { id: tenantId, name: tenantId }
})

onMounted(() => {
  // Fetch dashboard stats
  // This would be an API call in a real application
  console.log(`Loading dashboard for tenant: ${route.params.tenantId}`)
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