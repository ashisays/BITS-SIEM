<template>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <h1>BITS SIEM</h1>
        <p>Security Information and Event Management</p>
      </div>
      
      <form @submit.prevent="handleLogin" class="login-form">
        <div class="form-group">
          <label for="email">Email</label>
          <input 
            id="email"
            v-model="credentials.email" 
            type="email" 
            required 
            placeholder="Enter your email"
          />
        </div>
        
        <div class="form-group">
          <label for="password">Password</label>
          <input 
            id="password"
            v-model="credentials.password" 
            type="password" 
            required 
            placeholder="Enter your password"
          />
        </div>
        
        <div class="form-group" v-if="showTenantSelect">
          <label for="tenant">Select Tenant</label>
          <select id="tenant" v-model="credentials.tenantId" required>
            <option value="">Choose a tenant...</option>
            <option v-for="tenant in availableTenants" :key="tenant.id" :value="tenant.id">
              {{ tenant.name }}
            </option>
          </select>
        </div>
        
        <button type="submit" class="login-btn" :disabled="isLoading">
          {{ isLoading ? 'Signing in...' : 'Sign In' }}
        </button>
        
        <div v-if="error" class="error-message">
          {{ error }}
        </div>
      </form>
      
      <div class="login-footer">
        <p>Don't have an account? <router-link to="/register">Register here</router-link></p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../composables/useAuth'
import api from '../services/api'

const router = useRouter()
const { setAuth, clearAuth } = useAuth()

const credentials = ref({
  email: '',
  password: '',
  tenantId: ''
})

const availableTenants = ref([])
const showTenantSelect = ref(false)
const isLoading = ref(false)
const error = ref('')

const fetchUserTenants = async (email) => {
  try {
    const tenants = await api.getTenants(email)
    availableTenants.value = tenants
    showTenantSelect.value = tenants.length > 1
    if (tenants.length === 1) {
      credentials.value.tenantId = tenants[0].id
    }
  } catch (err) {
    console.error('Error fetching tenants:', err)
    // Mock data for development
    availableTenants.value = [
      { id: 'acme-corp', name: 'Acme Corporation' },
      { id: 'beta-industries', name: 'Beta Industries' }
    ]
    showTenantSelect.value = true
  }
}

const handleLogin = async () => {
  error.value = ''
  isLoading.value = true
  
  try {
    // First check if we need to fetch tenants
    if (!credentials.value.tenantId && availableTenants.value.length === 0) {
      await fetchUserTenants(credentials.value.email)
      if (showTenantSelect.value) {
        isLoading.value = false
        return // Wait for tenant selection
      }
    }
    
    const data = await api.login({
      email: credentials.value.email,
      password: credentials.value.password,
      tenantId: credentials.value.tenantId
    })
    
    // Use auth composable to manage session
    setAuth(data.token, data.user, data.user.tenantId)
    
    // Redirect to tenant dashboard
    router.push(`/tenant/${data.user.tenantId}/dashboard`)
  } catch (err) {
    console.error('Login error:', err)
    error.value = 'Network error. Please try again.'
    
    // Mock successful login for development
    if (credentials.value.email && credentials.value.password) {
      const mockUser = {
        id: '1',
        email: credentials.value.email,
        name: 'Demo User',
        tenantId: credentials.value.tenantId || 'acme-corp',
        role: credentials.value.email.includes('admin') ? 'admin' : 'user'
      }
      
      setAuth('mock-jwt-token', mockUser, mockUser.tenantId)
      
      router.push(`/tenant/${mockUser.tenantId}/dashboard`)
    }
  } finally {
    isLoading.value = false
  }
}

// Auto-fetch tenants when email changes
const emailChanged = () => {
  if (credentials.value.email.includes('@')) {
    fetchUserTenants(credentials.value.email)
  }
}

onMounted(() => {
  // Clear any existing auth data
  clearAuth()
})
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.login-card {
  background: white;
  border-radius: 12px;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
  padding: 48px;
  width: 100%;
  max-width: 480px;
  min-width: 400px;
}

@media (max-width: 640px) {
  .login-card {
    padding: 32px;
    max-width: 100%;
    min-width: auto;
  }
}

.login-header {
  text-align: center;
  margin-bottom: 30px;
}

.login-header h1 {
  font-size: 2.75rem;
  font-weight: 700;
  color: #333;
  margin: 0 0 12px 0;
  letter-spacing: -0.025em;
}

.login-header p {
  color: #666;
  margin: 0;
  font-size: 1.125rem;
  font-weight: 400;
}

@media (max-width: 640px) {
  .login-header h1 {
    font-size: 2.25rem;
  }
  
  .login-header p {
    font-size: 1rem;
  }
}

.form-group {
  margin-bottom: 24px;
}

.form-group label {
  display: block;
  margin-bottom: 10px;
  font-weight: 600;
  color: #333;
  font-size: 0.95rem;
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 14px 18px;
  border: 2px solid #e1e5e9;
  border-radius: 8px;
  font-size: 16px;
  transition: all 0.2s ease;
  box-sizing: border-box;
  background-color: #fff;
}

@media (max-width: 640px) {
  .form-group {
    margin-bottom: 20px;
  }
  
  .form-group input,
  .form-group select {
    padding: 12px 16px;
  }
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #667eea;
}

.login-btn {
  width: 100%;
  padding: 16px 24px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 8px;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.25);
}

.login-btn:hover:not(:disabled) {
  transform: translateY(-2px);
}

.login-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
  transform: none;
}

.error-message {
  color: #dc3545;
  text-align: center;
  margin-top: 15px;
  padding: 10px;
  background-color: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 4px;
}

.login-footer {
  text-align: center;
  margin-top: 30px;
  padding-top: 20px;
  border-top: 1px solid #e1e5e9;
}

.login-footer a {
  color: #667eea;
  text-decoration: none;
  font-weight: 600;
}

.login-footer a:hover {
  text-decoration: underline;
}
</style>
