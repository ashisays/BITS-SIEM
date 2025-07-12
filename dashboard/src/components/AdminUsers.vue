<template>
  <div class="admin-users">
    <div class="header">
      <h2>User Management</h2>
      <button @click="showCreateModal = true" class="btn btn-primary">
        Add New User
      </button>
    </div>
    
    <div class="filters">
      <select v-model="selectedTenant" @change="fetchUsers" class="tenant-filter">
        <option value="">All Tenants</option>
        <option v-for="tenant in tenants" :key="tenant.id" :value="tenant.id">
          {{ tenant.name }}
        </option>
      </select>
    </div>
    
    <div class="users-list">
      <div v-for="user in filteredUsers" :key="user.id" class="user-card">
        <div class="user-info">
          <h3>{{ user.name }}</h3>
          <p class="user-email">{{ user.email }}</p>
          <p class="user-role" :class="user.role">
            Role: {{ user.role }}
          </p>
          <p class="user-tenant">Tenant: {{ user.tenantName }}</p>
          <p class="user-status" :class="user.status">
            Status: {{ user.status }}
          </p>
        </div>
        <div class="user-actions">
          <button @click="editUser(user)" class="btn btn-outline">
            Edit
          </button>
          <button @click="toggleUserStatus(user)" class="btn btn-warning">
            {{ user.status === 'active' ? 'Suspend' : 'Activate' }}
          </button>
          <button @click="deleteUser(user)" class="btn btn-danger">
            Delete
          </button>
        </div>
      </div>
    </div>
    
    <!-- Create/Edit User Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <h3>{{ editingUser ? 'Edit User' : 'Create New User' }}</h3>
        <form @submit.prevent="saveUser">
          <div class="form-group">
            <label>Name</label>
            <input v-model="userForm.name" type="text" required />
          </div>
          <div class="form-group">
            <label>Email</label>
            <input v-model="userForm.email" type="email" required />
          </div>
          <div class="form-group">
            <label>Password</label>
            <input v-model="userForm.password" type="password" :required="!editingUser" />
          </div>
          <div class="form-group">
            <label>Role</label>
            <select v-model="userForm.role" required>
              <option value="user">User</option>
              <option value="admin">Admin</option>
              <option value="analyst">Security Analyst</option>
            </select>
          </div>
          <div class="form-group">
            <label>Tenant</label>
            <select v-model="userForm.tenantId" required>
              <option value="">Select Tenant</option>
              <option v-for="tenant in tenants" :key="tenant.id" :value="tenant.id">
                {{ tenant.name }}
              </option>
            </select>
          </div>
          <div class="form-actions">
            <button type="button" @click="closeModal" class="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary">
              {{ editingUser ? 'Update' : 'Create' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'

const users = ref([])
const tenants = ref([])
const selectedTenant = ref('')
const showCreateModal = ref(false)
const editingUser = ref(null)
const userForm = ref({
  name: '',
  email: '',
  password: '',
  role: 'user',
  tenantId: ''
})

const filteredUsers = computed(() => {
  if (!selectedTenant.value) return users.value
  return users.value.filter(user => user.tenantId === selectedTenant.value)
})

const fetchTenants = async () => {
  try {
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
    // Mock data
    tenants.value = [
      { id: 'acme-corp', name: 'Acme Corporation' },
      { id: 'beta-industries', name: 'Beta Industries' }
    ]
  }
}

const fetchUsers = async () => {
  try {
    const url = selectedTenant.value 
      ? `/api/admin/users?tenantId=${selectedTenant.value}`
      : '/api/admin/users'
    
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      }
    })
    if (response.ok) {
      users.value = await response.json()
    }
  } catch (error) {
    console.error('Error fetching users:', error)
    // Mock data
    users.value = [
      {
        id: '1',
        name: 'John Doe',
        email: 'john@acme.com',
        role: 'admin',
        tenantId: 'acme-corp',
        tenantName: 'Acme Corporation',
        status: 'active'
      },
      {
        id: '2', 
        name: 'Jane Smith',
        email: 'jane@acme.com',
        role: 'analyst',
        tenantId: 'acme-corp',
        tenantName: 'Acme Corporation',
        status: 'active'
      },
      {
        id: '3',
        name: 'Bob Wilson',
        email: 'bob@beta.com',
        role: 'user',
        tenantId: 'beta-industries',
        tenantName: 'Beta Industries',
        status: 'suspended'
      }
    ]
  }
}

const editUser = (user) => {
  editingUser.value = user
  userForm.value = { ...user, password: '' }
  showCreateModal.value = true
}

const closeModal = () => {
  showCreateModal.value = false
  editingUser.value = null
  userForm.value = {
    name: '',
    email: '',
    password: '',
    role: 'user',
    tenantId: ''
  }
}

const saveUser = async () => {
  try {
    const url = editingUser.value 
      ? `/api/admin/users/${editingUser.value.id}`
      : '/api/admin/users'
    
    const method = editingUser.value ? 'PUT' : 'POST'
    
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      },
      body: JSON.stringify(userForm.value)
    })
    
    if (response.ok) {
      await fetchUsers()
      closeModal()
    }
  } catch (error) {
    console.error('Error saving user:', error)
  }
}

const toggleUserStatus = async (user) => {
  try {
    const newStatus = user.status === 'active' ? 'suspended' : 'active'
    const response = await fetch(`/api/admin/users/${user.id}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      },
      body: JSON.stringify({ status: newStatus })
    })
    
    if (response.ok) {
      user.status = newStatus
    }
  } catch (error) {
    console.error('Error updating user status:', error)
  }
}

const deleteUser = async (user) => {
  if (!confirm(`Are you sure you want to delete user ${user.name}?`)) return
  
  try {
    const response = await fetch(`/api/admin/users/${user.id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
      }
    })
    
    if (response.ok) {
      await fetchUsers()
    }
  } catch (error) {
    console.error('Error deleting user:', error)
  }
}

onMounted(async () => {
  await fetchTenants()
  await fetchUsers()
})
</script>

<style scoped>
.admin-users {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.filters {
  margin-bottom: 20px;
}

.tenant-filter {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.users-list {
  display: grid;
  gap: 20px;
}

.user-card {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.user-info h3 {
  margin: 0 0 10px 0;
  color: #333;
}

.user-email {
  color: #666;
  margin: 5px 0;
}

.user-role {
  margin: 5px 0;
  font-weight: bold;
}

.user-role.admin {
  color: #dc3545;
}

.user-role.analyst {
  color: #ffc107;
}

.user-role.user {
  color: #28a745;
}

.user-tenant {
  color: #666;
  margin: 5px 0;
}

.user-status {
  margin: 5px 0;
  font-weight: bold;
}

.user-status.active {
  color: #28a745;
}

.user-status.suspended {
  color: #dc3545;
}

.user-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.btn-danger {
  background-color: #dc3545;
  color: white;
}

.btn-danger:hover {
  background-color: #c82333;
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
.form-group select {
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
