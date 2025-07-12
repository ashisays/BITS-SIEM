<template>
  <div class="admin-tenants">
    <div class="header">
      <h2>Tenant Management</h2>
      <button @click="showCreateModal = true" class="btn btn-primary">
        Add New Tenant
      </button>
    </div>
    
    <div class="tenants-list">
      <div v-for="tenant in tenants" :key="tenant.id" class="tenant-card">
        <div class="tenant-info">
          <h3>{{ tenant.name }}</h3>
          <p class="tenant-id">ID: {{ tenant.id }}</p>
          <p class="tenant-status" :class="tenant.status">
            Status: {{ tenant.status }}
          </p>
          <p class="tenant-users">Users: {{ tenant.userCount }}</p>
        </div>
        <div class="tenant-actions">
          <button @click="viewTenant(tenant.id)" class="btn btn-secondary">
            View Dashboard
          </button>
          <button @click="editTenant(tenant)" class="btn btn-outline">
            Edit
          </button>
          <button @click="toggleTenantStatus(tenant)" class="btn btn-warning">
            {{ tenant.status === 'active' ? 'Suspend' : 'Activate' }}
          </button>
        </div>
      </div>
    </div>
    
    <!-- Create/Edit Tenant Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <h3>{{ editingTenant ? 'Edit Tenant' : 'Create New Tenant' }}</h3>
        <form @submit.prevent="saveTenant">
          <div class="form-group">
            <label>Tenant Name</label>
            <input v-model="tenantForm.name" type="text" required />
          </div>
          <div class="form-group">
            <label>Domain</label>
            <input v-model="tenantForm.domain" type="text" />
          </div>
          <div class="form-group">
            <label>Description</label>
            <textarea v-model="tenantForm.description" rows="3"></textarea>
          </div>
          <div class="form-actions">
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
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

const tenants = ref([])
const showCreateModal = ref(false)
const editingTenant = ref(null)
const tenantForm = ref({
  name: '',
  domain: '',
  description: ''
})

const fetchTenants = async () => {
  try {
    // Replace with actual API call
    const response = await fetch('/api/admin/tenants', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      }
    })
    if (response.ok) {
      tenants.value = await response.json()
    }
  } catch (error) {
    console.error('Error fetching tenants:', error)
    // Mock data for development
    tenants.value = [
      {
        id: 'tenant-1',
        name: 'Acme Corporation',
        domain: 'acme.com',
        status: 'active',
        userCount: 15,
        description: 'Main corporate tenant'
      },
      {
        id: 'tenant-2', 
        name: 'Beta Industries',
        domain: 'beta.com',
        status: 'active',
        userCount: 8,
        description: 'Beta testing environment'
      }
    ]
  }
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
    description: ''
  }
}

const saveTenant = async () => {
  try {
    const url = editingTenant.value 
      ? `/api/admin/tenants/${editingTenant.value.id}`
      : '/api/admin/tenants'
    
    const method = editingTenant.value ? 'PUT' : 'POST'
    
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      },
      body: JSON.stringify(tenantForm.value)
    })
    
    if (response.ok) {
      await fetchTenants()
      closeModal()
    }
  } catch (error) {
    console.error('Error saving tenant:', error)
  }
}

const toggleTenantStatus = async (tenant) => {
  try {
    const newStatus = tenant.status === 'active' ? 'suspended' : 'active'
    const response = await fetch(`/api/admin/tenants/${tenant.id}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      },
      body: JSON.stringify({ status: newStatus })
    })
    
    if (response.ok) {
      tenant.status = newStatus
    }
  } catch (error) {
    console.error('Error updating tenant status:', error)
  }
}

onMounted(() => {
  fetchTenants()
})
</script>

<style scoped>
.admin-tenants {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.tenants-list {
  display: grid;
  gap: 20px;
}

.tenant-card {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.tenant-info h3 {
  margin: 0 0 10px 0;
  color: #333;
}

.tenant-id {
  font-family: monospace;
  color: #666;
  margin: 5px 0;
}

.tenant-status {
  margin: 5px 0;
  font-weight: bold;
}

.tenant-status.active {
  color: #28a745;
}

.tenant-status.suspended {
  color: #dc3545;
}

.tenant-users {
  color: #666;
  margin: 5px 0;
}

.tenant-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
}

.btn-primary {
  background-color: #007bff;
  color: white;
}

.btn-secondary {
  background-color: #6c757d;
  color: white;
}

.btn-outline {
  background-color: transparent;
  border: 1px solid #007bff;
  color: #007bff;
}

.btn-warning {
  background-color: #ffc107;
  color: #212529;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal {
  background: white;
  padding: 30px;
  border-radius: 8px;
  width: 500px;
  max-width: 90vw;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: bold;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 20px;
}
</style>
