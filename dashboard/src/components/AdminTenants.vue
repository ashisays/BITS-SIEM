<template>
  <div class="admin-tenants">
    <div class="header">
      <h2>Tenant Management</h2>
      <div class="header-actions">
        <button @click="showCreateModal = true" class="btn btn-primary" v-if="canCreateTenants">
          Add New Tenant
        </button>
        <button @click="refreshTenants" class="btn btn-outline">
          <span class="refresh-icon">🔄</span>
        </button>
      </div>
    </div>

    <div class="tenants-stats">
      <div class="stat-card">
        <span class="stat-number">{{ totalTenants }}</span>
        <span class="stat-label">Total Tenants</span>
      </div>
      <div class="stat-card active">
        <span class="stat-number">{{ activeTenants }}</span>
        <span class="stat-label">Active</span>
      </div>
      <div class="stat-card suspended">
        <span class="stat-number">{{ suspendedTenants }}</span>
        <span class="stat-label">Suspended</span>
      </div>
      <div class="stat-card total-users">
        <span class="stat-number">{{ totalUsers }}</span>
        <span class="stat-label">Total Users</span>
      </div>
    </div>

    <div class="tenants-list">
      <div v-for="tenant in filteredTenants" :key="tenant.id" class="tenant-card">
        <div class="tenant-info">
          <div class="tenant-header">
            <h3>{{ tenant.name }}</h3>
            <span class="tenant-status" :class="tenant.status">
              {{ tenant.status }}
            </span>
          </div>
          <p class="tenant-id">ID: {{ tenant.id }}</p>
          <p class="tenant-domain" v-if="tenant.domain">Domain: {{ tenant.domain }}</p>
          <p class="tenant-description" v-if="tenant.description">{{ tenant.description }}</p>
          <div class="tenant-metrics">
            <span class="metric">
              <strong>{{ tenant.userCount }}</strong> Users
            </span>
            <span class="metric">
              <strong>{{ tenant.sourcesCount || 0 }}</strong> Sources
            </span>
            <span class="metric">
              <strong>{{ formatDate(tenant.createdAt) }}</strong> Created
            </span>
          </div>
        </div>
        <div class="tenant-actions">
          <button @click="viewTenant(tenant.id)" class="btn btn-secondary">
            View Dashboard
          </button>
          <button @click="editTenant(tenant)" class="btn btn-outline" v-if="canEditTenant(tenant)">
            Edit
          </button>
          <button @click="toggleTenantStatus(tenant)" class="btn btn-warning" v-if="canManageTenant(tenant)">
            {{ tenant.status === 'active' ? 'Suspend' : 'Activate' }}
          </button>
          <button @click="deleteTenant(tenant)" class="btn btn-danger" v-if="canDeleteTenant(tenant)">
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredTenants.length === 0" class="empty-state">
      <div class="empty-icon">🏢</div>
      <h3>No tenants found</h3>
      <p>No tenants match your current filters or you don't have access to view any tenants.</p>
    </div>

    <!-- Create/Edit Tenant Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <div class="modal-header">
          <h3>{{ editingTenant ? 'Edit Tenant' : 'Create New Tenant' }}</h3>
          <button @click="closeModal" class="modal-close">×</button>
        </div>
        <form @submit.prevent="saveTenant" class="modal-content">
          <div class="form-group">
            <label>Tenant Name *</label>
            <input v-model="tenantForm.name" type="text" required />
          </div>
          <div class="form-group">
            <label>Domain</label>
            <input v-model="tenantForm.domain" type="text" placeholder="example.com" />
          </div>
          <div class="form-group">
            <label>Description</label>
            <textarea v-model="tenantForm.description" rows="3" placeholder="Brief description of the tenant"></textarea>
          </div>
          <div class="form-group">
            <label>Status</label>
            <select v-model="tenantForm.status">
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
            </select>
          </div>
          <div class="modal-actions">
            <button type="button" @click="closeModal" class="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary">
              {{ editingTenant ? 'Update' : 'Create' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../composables/useAuth'
import api from '../services/api'

const router = useRouter()
const { user } = useAuth()

const tenants = ref([])
const showCreateModal = ref(false)
const editingTenant = ref(null)
const tenantForm = ref({
  name: '',
  domain: '',
  description: '',
  status: 'active'
})

// Computed properties
const filteredTenants = computed(() => {
  // Filter tenants based on user permissions
  if (!user.value) return []
  
  // Superadmin can see all tenants
  if (user.value.role === 'superadmin') {
    return tenants.value
  }
  
  // Regular admin can only see their own tenant
  if (user.value.role === 'admin') {
    return tenants.value.filter(tenant => tenant.id === user.value.tenantId)
  }
  
  // Other roles cannot see any tenants
  return []
})

const totalTenants = computed(() => filteredTenants.value.length)
const activeTenants = computed(() => filteredTenants.value.filter(t => t.status === 'active').length)
const suspendedTenants = computed(() => filteredTenants.value.filter(t => t.status === 'suspended').length)
const totalUsers = computed(() => filteredTenants.value.reduce((sum, t) => sum + (t.userCount || 0), 0))

// Permission checks
const canCreateTenants = computed(() => {
  return user.value?.role === 'superadmin'
})

const canEditTenant = (tenant) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && tenant.id === user.value.tenantId) return true
  return false
}

const canManageTenant = (tenant) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && tenant.id === user.value.tenantId) return true
  return false
}

const canDeleteTenant = (tenant) => {
  return user.value?.role === 'superadmin'
}

const fetchTenants = async () => {
  try {
    const response = await api.getAdminTenants()
    tenants.value = response.data || response
  } catch (error) {
    console.error('Error fetching tenants:', error)
    // Mock data for development
    tenants.value = [
      {
        id: 'acme-corp',
        name: 'Acme Corporation',
        domain: 'acme.com',
        status: 'active',
        userCount: 15,
        sourcesCount: 8,
        description: 'Main corporate tenant',
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'beta-industries',
        name: 'Beta Industries',
        domain: 'beta.com',
        status: 'active',
        userCount: 8,
        sourcesCount: 3,
        description: 'Beta testing environment',
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'cisco-systems',
        name: 'Cisco Systems',
        domain: 'cisco.com',
        status: 'active',
        userCount: 25,
        sourcesCount: 12,
        description: 'Cisco internal systems',
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'demo-org',
        name: 'Demo Organization',
        domain: 'demo.org',
        status: 'active',
        userCount: 5,
        sourcesCount: 2,
        description: 'Demo and testing environment',
        createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'bits-internal',
        name: 'BITS Internal',
        domain: 'bits.com',
        status: 'active',
        userCount: 3,
        sourcesCount: 5,
        description: 'BITS internal monitoring',
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
      }
    ]
  }
}

const refreshTenants = () => {
  fetchTenants()
}

const viewTenant = (tenantId) => {
  router.push(`/tenant/${tenantId}/dashboard`)
}

const editTenant = (tenant) => {
  editingTenant.value = tenant
  tenantForm.value = { ...tenant }
  showCreateModal.value = true
}

const closeModal = () => {
  showCreateModal.value = false
  editingTenant.value = null
  tenantForm.value = {
    name: '',
    domain: '',
    description: '',
    status: 'active'
  }
}

const saveTenant = async () => {
  try {
    if (editingTenant.value) {
      await api.updateTenant(editingTenant.value.id, tenantForm.value)
    } else {
      await api.createTenant(tenantForm.value)
    }
    
    await fetchTenants()
    closeModal()
  } catch (error) {
    console.error('Error saving tenant:', error)
    alert('Failed to save tenant. Please try again.')
  }
}

const toggleTenantStatus = async (tenant) => {
  try {
    const newStatus = tenant.status === 'active' ? 'suspended' : 'active'
    await api.updateTenantStatus(tenant.id, newStatus)
    tenant.status = newStatus
  } catch (error) {
    console.error('Error updating tenant status:', error)
    alert('Failed to update tenant status. Please try again.')
  }
}

const deleteTenant = async (tenant) => {
  if (!confirm(`Are you sure you want to delete tenant "${tenant.name}"? This action cannot be undone.`)) {
    return
  }
  
  try {
    await api.deleteTenant(tenant.id)
    await fetchTenants()
  } catch (error) {
    console.error('Error deleting tenant:', error)
    alert('Failed to delete tenant. Please try again.')
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'Unknown'
  const date = new Date(dateString)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

onMounted(() => {
  fetchTenants()
})
</script>

<style scoped>
.admin-tenants {
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  flex-wrap: wrap;
  gap: 16px;
}

.header h2 {
  margin: 0;
  color: #333;
  font-size: 24px;
  font-weight: 600;
}

.header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}

.refresh-icon {
  font-size: 16px;
}

.tenants-stats {
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

.stat-card.active {
  border-left: 4px solid #28a745;
}

.stat-card.suspended {
  border-left: 4px solid #dc3545;
}

.stat-card.total-users {
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

.tenants-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.tenant-card {
  background: white;
  border: 1px solid #e1e5e9;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  transition: all 0.2s ease;
}

.tenant-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.tenant-info {
  flex: 1;
}

.tenant-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.tenant-header h3 {
  margin: 0;
  color: #333;
  font-size: 18px;
  font-weight: 600;
}

.tenant-status {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.tenant-status.active {
  background: #d4edda;
  color: #155724;
}

.tenant-status.suspended {
  background: #f8d7da;
  color: #721c24;
}

.tenant-id {
  font-family: monospace;
  color: #666;
  margin: 4px 0;
  font-size: 12px;
}

.tenant-domain {
  color: #007bff;
  margin: 4px 0;
  font-size: 14px;
}

.tenant-description {
  color: #666;
  margin: 8px 0;
  font-size: 14px;
  line-height: 1.4;
}

.tenant-metrics {
  display: flex;
  gap: 16px;
  margin-top: 12px;
}

.metric {
  font-size: 12px;
  color: #666;
}

.metric strong {
  color: #333;
}

.tenant-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: flex-start;
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
  max-width: 500px;
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

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  margin-bottom: 6px;
  font-weight: 500;
  color: #333;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  background: white;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  padding-top: 20px;
  border-top: 1px solid #e1e5e9;
}

@media (max-width: 768px) {
  .admin-tenants {
    padding: 16px;
  }
  
  .header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .header-actions {
    justify-content: space-between;
  }
  
  .tenants-stats {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .tenant-card {
    flex-direction: column;
    gap: 16px;
  }
  
  .tenant-actions {
    justify-content: flex-start;
  }
  
  .modal {
    width: 95%;
    margin: 20px;
  }
}
</style>
