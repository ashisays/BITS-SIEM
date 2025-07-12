<template>
  <nav class="navbar" v-if="isAuthenticated">
    <div class="navbar-container">
      <!-- Logo and Brand -->
      <div class="navbar-brand">
        <router-link to="/" class="brand-link">
          <h2>BITS SIEM</h2>
        </router-link>
        <span class="tenant-badge" v-if="currentTenant">
          {{ currentTenant.name }}
        </span>
      </div>

      <!-- Navigation Links -->
      <div class="navbar-nav">
        <div class="nav-section" v-if="currentTenantId">
          <router-link 
            :to="`/tenant/${currentTenantId}/dashboard`" 
            class="nav-link"
            active-class="active"
          >
            <i class="icon">📊</i>
            Dashboard
          </router-link>
          
          <router-link 
            :to="`/tenant/${currentTenantId}/sources`" 
            class="nav-link"
            active-class="active"
          >
            <i class="icon">🔌</i>
            Sources
          </router-link>
          
          <router-link 
            :to="`/tenant/${currentTenantId}/notifications`" 
            class="nav-link"
            active-class="active"
          >
            <i class="icon">🔔</i>
            Notifications
          </router-link>
          
          <router-link 
            :to="`/tenant/${currentTenantId}/reports`" 
            class="nav-link"
            active-class="active"
          >
            <i class="icon">📋</i>
            Reports
          </router-link>
        </div>

        <!-- Admin Links -->
        <div class="nav-section" v-if="isAdmin">
          <div class="nav-divider"></div>
          <router-link 
            to="/admin/tenants" 
            class="nav-link admin-link"
            active-class="active"
          >
            <i class="icon">🏢</i>
            Tenants
          </router-link>
          
          <router-link 
            to="/admin/users" 
            class="nav-link admin-link"
            active-class="active"
          >
            <i class="icon">👥</i>
            Users
          </router-link>
        </div>
      </div>

      <!-- User Menu -->
      <div class="navbar-user">
        <div class="user-dropdown" @click="toggleUserMenu">
          <div class="user-avatar">
            {{ userInitials }}
          </div>
          <span class="user-name">{{ user?.name || user?.email }}</span>
          <i class="dropdown-arrow">▼</i>
        </div>
        
        <div class="dropdown-menu" v-if="showUserMenu" @click.stop>
          <div class="dropdown-item user-info">
            <strong>{{ user?.name }}</strong>
            <small>{{ user?.email }}</small>
            <span class="role-badge" :class="user?.role">{{ user?.role }}</span>
          </div>
          
          <div class="dropdown-divider"></div>
          
          <div class="dropdown-item" v-if="user?.tenants?.length > 1">
            <label>Switch Tenant:</label>
            <select v-model="selectedTenantId" @change="switchTenant" class="tenant-switcher">
              <option v-for="tenant in user.tenants" :key="tenant.id" :value="tenant.id">
                {{ tenant.name }}
              </option>
            </select>
          </div>
          
          <div class="dropdown-divider" v-if="user?.tenants?.length > 1"></div>
          
          <button class="dropdown-item logout-btn" @click="logout">
            <i class="icon">🚪</i>
            Logout
          </button>
        </div>
      </div>

      <!-- Mobile Menu Toggle -->
      <button class="mobile-toggle" @click="toggleMobileMenu">
        <span></span>
        <span></span>
        <span></span>
      </button>
    </div>

    <!-- Mobile Menu -->
    <div class="mobile-menu" :class="{ active: showMobileMenu }">
      <div class="mobile-nav-links">
        <router-link 
          :to="`/tenant/${currentTenantId}/dashboard`" 
          class="mobile-nav-link"
          @click="closeMobileMenu"
        >
          📊 Dashboard
        </router-link>
        
        <router-link 
          :to="`/tenant/${currentTenantId}/sources`" 
          class="mobile-nav-link"
          @click="closeMobileMenu"
        >
          🔌 Sources
        </router-link>
        
        <router-link 
          :to="`/tenant/${currentTenantId}/notifications`" 
          class="mobile-nav-link"
          @click="closeMobileMenu"
        >
          🔔 Notifications
        </router-link>
        
        <router-link 
          :to="`/tenant/${currentTenantId}/reports`" 
          class="mobile-nav-link"
          @click="closeMobileMenu"
        >
          📋 Reports
        </router-link>
        
        <div class="mobile-divider" v-if="isAdmin"></div>
        
        <router-link 
          to="/admin/tenants" 
          class="mobile-nav-link admin-link"
          @click="closeMobileMenu"
          v-if="isAdmin"
        >
          🏢 Tenants
        </router-link>
        
        <router-link 
          to="/admin/users" 
          class="mobile-nav-link admin-link"
          @click="closeMobileMenu"
          v-if="isAdmin"
        >
          👥 Users
        </router-link>
      </div>
    </div>
  </nav>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()

const showUserMenu = ref(false)
const showMobileMenu = ref(false)
const selectedTenantId = ref('')

// Authentication state
const isAuthenticated = computed(() => !!localStorage.getItem('jwt'))
const user = computed(() => {
  try {
    const userStr = localStorage.getItem('user')
    return userStr ? JSON.parse(userStr) : null
  } catch {
    return null
  }
})

const currentTenantId = computed(() => {
  return route.params.tenantId || localStorage.getItem('currentTenantId')
})

const currentTenant = computed(() => {
  if (!currentTenantId.value) return null
  // This would normally come from a store or API call
  const tenants = {
    'acme-corp': { id: 'acme-corp', name: 'Acme Corporation' },
    'beta-industries': { id: 'beta-industries', name: 'Beta Industries' }
  }
  return tenants[currentTenantId.value] || { id: currentTenantId.value, name: currentTenantId.value }
})

const isAdmin = computed(() => {
  return user.value?.role === 'admin' || user.value?.roles?.includes('admin')
})

const userInitials = computed(() => {
  if (!user.value) return 'U'
  if (user.value.name) {
    return user.value.name.split(' ').map(n => n[0]).join('').toUpperCase()
  }
  return user.value.email?.[0]?.toUpperCase() || 'U'
})

const toggleUserMenu = () => {
  showUserMenu.value = !showUserMenu.value
  showMobileMenu.value = false
}

const toggleMobileMenu = () => {
  showMobileMenu.value = !showMobileMenu.value
  showUserMenu.value = false
}

const closeMobileMenu = () => {
  showMobileMenu.value = false
}

const switchTenant = () => {
  if (selectedTenantId.value && selectedTenantId.value !== currentTenantId.value) {
    localStorage.setItem('currentTenantId', selectedTenantId.value)
    router.push(`/tenant/${selectedTenantId.value}/dashboard`)
  }
}

const logout = () => {
  localStorage.removeItem('jwt')
  localStorage.removeItem('user')
  localStorage.removeItem('currentTenantId')
  router.push('/login')
}

// Close menus when clicking outside
const handleClickOutside = (event) => {
  if (!event.target.closest('.navbar-user')) {
    showUserMenu.value = false
  }
  if (!event.target.closest('.mobile-menu') && !event.target.closest('.mobile-toggle')) {
    showMobileMenu.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
  selectedTenantId.value = currentTenantId.value
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>

<style scoped>
.navbar {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  position: sticky;
  top: 0;
  z-index: 1000;
}

.navbar-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 64px;
}

.navbar-brand {
  display: flex;
  align-items: center;
  gap: 15px;
}

.brand-link {
  text-decoration: none;
  color: white;
}

.brand-link h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: bold;
}

.tenant-badge {
  background: rgba(255, 255, 255, 0.2);
  color: white;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
}

.navbar-nav {
  display: flex;
  align-items: center;
  gap: 30px;
}

.nav-section {
  display: flex;
  align-items: center;
  gap: 20px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 8px;
  color: rgba(255, 255, 255, 0.8);
  text-decoration: none;
  padding: 8px 16px;
  border-radius: 6px;
  transition: all 0.2s ease;
  font-weight: 500;
}

.nav-link:hover {
  color: white;
  background: rgba(255, 255, 255, 0.1);
}

.nav-link.active {
  color: white;
  background: rgba(255, 255, 255, 0.2);
}

.admin-link {
  border-left: 2px solid rgba(255, 255, 255, 0.3);
  padding-left: 20px;
}

.nav-divider {
  width: 1px;
  height: 30px;
  background: rgba(255, 255, 255, 0.3);
}

.navbar-user {
  position: relative;
}

.user-dropdown {
  display: flex;
  align-items: center;
  gap: 10px;
  color: white;
  cursor: pointer;
  padding: 8px 12px;
  border-radius: 6px;
  transition: background 0.2s ease;
}

.user-dropdown:hover {
  background: rgba(255, 255, 255, 0.1);
}

.user-avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 14px;
}

.user-name {
  font-weight: 500;
}

.dropdown-arrow {
  font-size: 10px;
  transition: transform 0.2s ease;
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  right: 0;
  background: white;
  border-radius: 8px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
  min-width: 250px;
  margin-top: 8px;
  overflow: hidden;
}

.dropdown-item {
  padding: 12px 16px;
  color: #333;
  border: none;
  background: none;
  width: 100%;
  text-align: left;
  cursor: pointer;
  transition: background 0.2s ease;
}

.dropdown-item:hover {
  background: #f5f5f5;
}

.user-info {
  cursor: default;
}

.user-info:hover {
  background: none;
}

.user-info strong {
  display: block;
  margin-bottom: 4px;
}

.user-info small {
  color: #666;
  display: block;
  margin-bottom: 8px;
}

.role-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.7rem;
  font-weight: 500;
  text-transform: uppercase;
}

.role-badge.admin {
  background: #dc3545;
  color: white;
}

.role-badge.analyst {
  background: #ffc107;
  color: #333;
}

.role-badge.user {
  background: #28a745;
  color: white;
}

.dropdown-divider {
  height: 1px;
  background: #e9ecef;
  margin: 8px 0;
}

.tenant-switcher {
  width: 100%;
  padding: 4px 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
  margin-top: 4px;
}

.logout-btn {
  color: #dc3545 !important;
  display: flex;
  align-items: center;
  gap: 8px;
}

.logout-btn:hover {
  background: #f8f9fa !important;
}

.mobile-toggle {
  display: none;
  flex-direction: column;
  gap: 4px;
  background: none;
  border: none;
  cursor: pointer;
  padding: 8px;
}

.mobile-toggle span {
  width: 25px;
  height: 3px;
  background: white;
  border-radius: 2px;
  transition: all 0.2s ease;
}

.mobile-menu {
  display: none;
  background: rgba(0, 0, 0, 0.9);
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  padding: 20px;
}

.mobile-nav-links {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.mobile-nav-link {
  color: white;
  text-decoration: none;
  padding: 12px 16px;
  border-radius: 6px;
  transition: background 0.2s ease;
}

.mobile-nav-link:hover {
  background: rgba(255, 255, 255, 0.1);
}

.mobile-divider {
  height: 1px;
  background: rgba(255, 255, 255, 0.3);
  margin: 10px 0;
}

.icon {
  font-size: 16px;
}

/* Mobile Styles */
@media (max-width: 768px) {
  .navbar-nav {
    display: none;
  }
  
  .mobile-toggle {
    display: flex;
  }
  
  .mobile-menu {
    display: block;
    transform: translateY(-100%);
    transition: transform 0.3s ease;
  }
  
  .mobile-menu.active {
    transform: translateY(0);
  }
  
  .user-name {
    display: none;
  }
}

@media (max-width: 480px) {
  .navbar-container {
    padding: 0 15px;
  }
  
  .tenant-badge {
    display: none;
  }
}
</style>
