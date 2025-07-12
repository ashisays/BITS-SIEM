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
  min-height: calc(100vh - 64px);
}

.dashboard-header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 40px 0;
}

.dashboard-header h1 {
  font-size: 2.5rem;
  font-weight: bold;
  margin: 0 0 10px 0;
}

.dashboard-subtitle {
  font-size: 1.1rem;
  opacity: 0.9;
  margin: 0;
}

.dashboard-content {
  padding: 40px 0;
}

.dashboard-grid {
  display: grid;
  gap: 30px;
  grid-template-columns: 1fr;
}

.dashboard-card {
  background: white;
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  border: 1px solid #e9ecef;
}

.dashboard-card h2 {
  margin: 0 0 20px 0;
  color: #333;
  font-size: 1.5rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 20px;
}

.stat-item {
  text-align: center;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.stat-number {
  display: block;
  font-size: 2rem;
  font-weight: bold;
  color: #667eea;
  margin-bottom: 5px;
}

.stat-label {
  font-size: 0.9rem;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
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
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .dashboard-grid {
    grid-template-columns: 1fr 1fr;
  }
  
  .dashboard-card {
    grid-column: 1 / -1;
  }
}

@media (max-width: 768px) {
  .dashboard-header h1 {
    font-size: 2rem;
  }
  
  .dashboard-content {
    padding: 20px 0;
  }
  
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>