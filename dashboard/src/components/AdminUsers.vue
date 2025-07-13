<template>
  <div class="admin-users">
    <div class="header">
      <h2>User Management</h2>
      <div class="header-actions">
        <button @click="showCreateModal = true" class="btn btn-primary" v-if="canCreateUsers">
          Add New User
        </button>
        <button @click="refreshUsers" class="btn btn-outline">
          <span class="refresh-icon">🔄</span>
        </button>
      </div>
    </div>

    <div class="filters">
      <select v-model="selectedTenant" @change="fetchUsers" class="tenant-filter" v-if="canViewAllTenants">
        <option value="">All Tenants</option>
        <option v-for="tenant in availableTenants" :key="tenant.id" :value="tenant.id">
          {{ tenant.name }}
        </option>
      </select>
      <select v-model="selectedRole" class="role-filter">
        <option value="">All Roles</option>
        <option value="admin">Admin</option>
        <option value="user">User</option>
        <option value="analyst">Security Analyst</option>
        <option value="sre">SRE</option>
      </select>
      <input 
        v-model="searchQuery" 
        type="text" 
        placeholder="Search users..." 
        class="search-input"
      />
    </div>

    <div class="users-stats">
      <div class="stat-card">
        <span class="stat-number">{{ totalUsers }}</span>
        <span class="stat-label">Total Users</span>
      </div>
      <div class="stat-card admin">
        <span class="stat-number">{{ adminCount }}</span>
        <span class="stat-label">Admins</span>
      </div>
      <div class="stat-card active">
        <span class="stat-number">{{ activeUsers }}</span>
        <span class="stat-label">Active</span>
      </div>
      <div class="stat-card suspended">
        <span class="stat-number">{{ suspendedUsers }}</span>
        <span class="stat-label">Suspended</span>
      </div>
    </div>

    <div class="users-list">
      <div v-for="user in paginatedUsers" :key="user.id" class="user-card">
        <div class="user-info">
          <div class="user-header">
            <h3>{{ user.name }}</h3>
            <span class="user-status" :class="user.status">
              {{ user.status }}
            </span>
          </div>
          <p class="user-email">{{ user.email }}</p>
          <div class="user-details">
            <span class="user-role" :class="user.role">
              {{ user.role }}
            </span>
            <span class="user-tenant">{{ user.tenantName }}</span>
          </div>
          <div class="user-meta">
            <span class="meta-item">
              <strong>Last Login:</strong> {{ formatDate(user.lastLogin) }}
            </span>
            <span class="meta-item">
              <strong>Created:</strong> {{ formatDate(user.createdAt) }}
            </span>
          </div>
        </div>
        <div class="user-actions">
          <button @click="editUser(user)" class="btn btn-outline" v-if="canEditUser(user)">
            Edit
          </button>
          <button @click="toggleUserStatus(user)" class="btn btn-warning" v-if="canManageUser(user)">
            {{ user.status === 'active' ? 'Suspend' : 'Activate' }}
          </button>
          <button @click="deleteUser(user)" class="btn btn-danger" v-if="canDeleteUser(user)">
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="paginatedUsers.length === 0" class="empty-state">
      <div class="empty-icon">👥</div>
      <h3>No users found</h3>
      <p>No users match your current filters or you don't have access to view any users.</p>
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

    <!-- Create/Edit User Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <div class="modal-header">
          <h3>{{ editingUser ? 'Edit User' : 'Create New User' }}</h3>
          <button @click="closeModal" class="modal-close">×</button>
        </div>
        <form @submit.prevent="saveUser" class="modal-content">
          <div class="form-group">
            <label>Name *</label>
            <input v-model="userForm.name" type="text" required />
          </div>
          <div class="form-group">
            <label>Email *</label>
            <input v-model="userForm.email" type="email" required />
          </div>
          <div class="form-group">
            <label>Password {{ editingUser ? '(leave blank to keep current)' : '*' }}</label>
            <input v-model="userForm.password" type="password" :required="!editingUser" />
          </div>
          <div class="form-group">
            <label>Role *</label>
            <select v-model="userForm.role" required>
              <option value="user">User</option>
              <option value="admin">Admin</option>
              <option value="analyst">Security Analyst</option>
              <option value="sre" v-if="canAssignSreRole">SRE</option>
            </select>
          </div>
          <div class="form-group">
            <label>Tenant *</label>
            <select v-model="userForm.tenantId" required>
              <option value="">Select Tenant</option>
              <option v-for="tenant in availableTenants" :key="tenant.id" :value="tenant.id">
                {{ tenant.name }}
              </option>
            </select>
            <small v-if="userForm.tenantId && !canCreateUsersForTenant(userForm.tenantId)" class="error-text">
              You can only create users for your own tenant.
            </small>
          </div>
          <div class="form-group">
            <label>Status</label>
            <select v-model="userForm.status">
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
            </select>
          </div>
          <div class="modal-actions">
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
import { useAuth } from '../composables/useAuth'
import api from '../services/api'

const { user } = useAuth()

const users = ref([])
const tenants = ref([])
const selectedTenant = ref('')
const selectedRole = ref('')
const searchQuery = ref('')
const currentPage = ref(1)
const itemsPerPage = 10
const showCreateModal = ref(false)
const editingUser = ref(null)
const userForm = ref({
  name: '',
  email: '',
  password: '',
  role: 'user',
  tenantId: '',
  status: 'active'
})

// Computed properties
const availableTenants = computed(() => {
  if (!user.value) return []
  
  // Superadmin can see all tenants
  if (user.value.role === 'superadmin') {
    return tenants.value
  }
  
  // Regular admin can only see their own tenant
  if (user.value.role === 'admin') {
    return tenants.value.filter(tenant => tenant.id === user.value.tenantId)
  }
  
  return []
})

const filteredUsers = computed(() => {
  let filtered = users.value

  if (selectedTenant.value) {
    filtered = filtered.filter(u => u.tenantId === selectedTenant.value)
  }

  if (selectedRole.value) {
    filtered = filtered.filter(u => u.role === selectedRole.value)
  }

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(u => 
      u.name.toLowerCase().includes(query) ||
      u.email.toLowerCase().includes(query)
    )
  }

  return filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
})

const paginatedUsers = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return filteredUsers.value.slice(start, end)
})

const totalPages = computed(() => {
  return Math.ceil(filteredUsers.value.length / itemsPerPage)
})

const totalUsers = computed(() => filteredUsers.value.length)
const adminCount = computed(() => filteredUsers.value.filter(u => u.role === 'admin').length)
const activeUsers = computed(() => filteredUsers.value.filter(u => u.status === 'active').length)
const suspendedUsers = computed(() => filteredUsers.value.filter(u => u.status === 'suspended').length)

// Permission checks
const canViewAllTenants = computed(() => {
  return user.value?.role === 'superadmin'
})

const canCreateUsers = computed(() => {
  return user.value?.role === 'superadmin' || user.value?.role === 'admin'
})

const canCreateUsersForTenant = (tenantId) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && tenantId === user.value.tenantId) return true
  return false
}

const canEditUser = (targetUser) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && targetUser.tenantId === user.value.tenantId) return true
  return false
}

const canManageUser = (targetUser) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && targetUser.tenantId === user.value.tenantId) return true
  return false
}

const canDeleteUser = (targetUser) => {
  if (user.value?.role === 'superadmin') return true
  if (user.value?.role === 'admin' && targetUser.tenantId === user.value.tenantId && targetUser.role !== 'admin') return true
  return false
}

const canAssignSreRole = computed(() => {
  return user.value?.role === 'superadmin'
})

const fetchTenants = async () => {
  try {
    const response = await api.getAdminTenants()
    tenants.value = response.data || response
  } catch (error) {
    console.error('Error fetching tenants:', error)
    // Mock data
    tenants.value = [
      { id: 'acme-corp', name: 'Acme Corporation' },
      { id: 'beta-industries', name: 'Beta Industries' },
      { id: 'cisco-systems', name: 'Cisco Systems' },
      { id: 'demo-org', name: 'Demo Organization' },
      { id: 'bits-internal', name: 'BITS Internal' }
    ]
  }
}

const fetchUsers = async () => {
  try {
    const response = await api.getAdminUsers(selectedTenant.value)
    users.value = response.data || response
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
        status: 'active',
        lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '2', 
        name: 'Jane Smith',
        email: 'jane@acme.com',
        role: 'analyst',
        tenantId: 'acme-corp',
        tenantName: 'Acme Corporation',
        status: 'active',
        lastLogin: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '3',
        name: 'Bob Wilson',
        email: 'bob@beta.com',
        role: 'user',
        tenantId: 'beta-industries',
        tenantName: 'Beta Industries',
        status: 'suspended',
        lastLogin: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '4',
        name: 'Aspundir Singh',
        email: 'aspundir@cisco.com',
        role: 'admin',
        tenantId: 'cisco-systems',
        tenantName: 'Cisco Systems',
        status: 'active',
        lastLogin: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '5',
        name: 'BITS SRE',
        email: 'sre@bits.com',
        role: 'sre',
        tenantId: 'bits-internal',
        tenantName: 'BITS Internal',
        status: 'active',
        lastLogin: new Date().toISOString(),
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
      }
    ]
  }
}

const refreshUsers = () => {
  fetchUsers()
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
    tenantId: '',
    status: 'active'
  }
}

const saveUser = async () => {
  try {
    // Check if user can create/edit users for this tenant
    if (!canCreateUsersForTenant(userForm.value.tenantId)) {
      alert('You can only create users for your own tenant.')
      return
    }
    
    if (editingUser.value) {
      await api.updateUser(editingUser.value.id, userForm.value)
    } else {
      await api.createUser(userForm.value)
    }
    
    await fetchUsers()
    closeModal()
  } catch (error) {
    console.error('Error saving user:', error)
    alert('Failed to save user. Please try again.')
  }
}

const toggleUserStatus = async (user) => {
  try {
    const newStatus = user.status === 'active' ? 'suspended' : 'active'
    await api.updateUserStatus(user.id, newStatus)
    user.status = newStatus
  } catch (error) {
    console.error('Error updating user status:', error)
    alert('Failed to update user status. Please try again.')
  }
}

const deleteUser = async (user) => {
  if (!confirm(`Are you sure you want to delete user "${user.name}"? This action cannot be undone.`)) {
    return
  }
  
  try {
    await api.deleteUser(user.id)
    await fetchUsers()
  } catch (error) {
    console.error('Error deleting user:', error)
    alert('Failed to delete user. Please try again.')
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'Never'
  const date = new Date(dateString)
  const now = new Date()
  const diff = now - date
  
  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

onMounted(() => {
  fetchTenants()
  fetchUsers()
})
</script>

<style scoped>
.admin-users {
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

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
  align-items: center;
}

.tenant-filter,
.role-filter {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  font-size: 14px;
  min-width: 150px;
}

.search-input {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  font-size: 14px;
  min-width: 200px;
}

.users-stats {
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

.stat-card.admin {
  border-left: 4px solid #6f42c1;
}

.stat-card.active {
  border-left: 4px solid #28a745;
}

.stat-card.suspended {
  border-left: 4px solid #dc3545;
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

.users-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-card {
  background: white;
  border: 1px solid #e1e5e9;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  transition: all 0.2s ease;
}

.user-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.user-info {
  flex: 1;
}

.user-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.user-header h3 {
  margin: 0;
  color: #333;
  font-size: 18px;
  font-weight: 600;
}

.user-status {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.user-status.active {
  background: #d4edda;
  color: #155724;
}

.user-status.suspended {
  background: #f8d7da;
  color: #721c24;
}

.user-email {
  color: #007bff;
  margin: 4px 0;
  font-size: 14px;
}

.user-details {
  display: flex;
  gap: 12px;
  margin: 8px 0;
  align-items: center;
}

.user-role {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.user-role.admin {
  background: #e2d9f3;
  color: #6f42c1;
}

.user-role.analyst {
  background: #fff3cd;
  color: #856404;
}

.user-role.sre {
  background: #d1ecf1;
  color: #0c5460;
}

.user-role.user {
  background: #d1e7dd;
  color: #0f5132;
}

.user-tenant {
  color: #666;
  font-size: 14px;
}

.user-meta {
  display: flex;
  gap: 16px;
  margin-top: 8px;
}

.meta-item {
  font-size: 12px;
  color: #666;
}

.meta-item strong {
  color: #333;
}

.user-actions {
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
.form-group select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  background: white;
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  padding-top: 20px;
  border-top: 1px solid #e1e5e9;
}

.error-text {
  color: #dc3545;
  font-size: 12px;
  margin-top: 4px;
  display: block;
}

@media (max-width: 768px) {
  .admin-users {
    padding: 16px;
  }
  
  .header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .header-actions {
    justify-content: space-between;
  }
  
  .filters {
    flex-direction: column;
    align-items: stretch;
  }
  
  .users-stats {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .user-card {
    flex-direction: column;
    gap: 16px;
  }
  
  .user-actions {
    justify-content: flex-start;
  }
  
  .modal {
    width: 95%;
    margin: 20px;
  }
}
</style>
