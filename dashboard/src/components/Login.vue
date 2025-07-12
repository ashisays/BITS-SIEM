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
  password: ''
})

const isLoading = ref(false)
const error = ref('')


const handleLogin = async () => {
  error.value = ''
  isLoading.value = true
  
  try {
    const data = await api.login({
      email: credentials.value.email,
      password: credentials.value.password
    })
    
    console.log('Login successful:', data)
    
    // Use auth composable to manage session
    setAuth(data.token, data.user, data.user.tenantId)
    
    // Redirect to user's tenant dashboard
    router.push(`/tenant/${data.user.tenantId}/dashboard`)
  } catch (err) {
    console.error('Login error:', err)
    
    // Parse error message
    if (err.message.includes('401')) {
      error.value = 'Invalid email or password'
    } else if (err.message.includes('403')) {
      error.value = 'Access denied'
    } else {
      error.value = 'Unable to connect to server. Please try again.'
    }
  } finally {
    isLoading.value = false
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
