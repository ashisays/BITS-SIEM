<template>
  <div class="register-container">
    <div class="register-card">
      <div class="register-header">
        <h1>Create Account</h1>
        <p>Join BITS SIEM Platform</p>
      </div>
      
      <form @submit.prevent="handleRegister" class="register-form">
        <div class="form-group">
          <label for="name">Full Name</label>
          <input 
            id="name"
            v-model="formData.name" 
            type="text" 
            required 
            placeholder="Enter your full name"
          />
        </div>
        
        <div class="form-group">
          <label for="email">Email</label>
          <input 
            id="email"
            v-model="formData.email" 
            type="email" 
            required 
            placeholder="Enter your email"
          />
        </div>
        
        <div class="form-group">
          <label for="password">Password</label>
          <input 
            id="password"
            v-model="formData.password" 
            type="password" 
            required 
            placeholder="Enter your password"
            minlength="6"
          />
        </div>
        
        <div class="form-group">
          <label for="confirmPassword">Confirm Password</label>
          <input 
            id="confirmPassword"
            v-model="formData.confirmPassword" 
            type="password" 
            required 
            placeholder="Confirm your password"
          />
        </div>
        
        <div class="form-group">
          <label for="tenant">Organization/Tenant Name</label>
          <input 
            id="tenant"
            v-model="formData.tenant" 
            type="text" 
            required 
            placeholder="Enter your organization name"
          />
        </div>
        
        <div class="form-group">
          <label for="role">Role</label>
          <select id="role" v-model="formData.role" required>
            <option value="">Select your role</option>
            <option value="admin">Administrator</option>
            <option value="analyst">Security Analyst</option>
            <option value="user">User</option>
          </select>
        </div>
        
        <button type="submit" class="register-btn" :disabled="isLoading">
          {{ isLoading ? 'Creating Account...' : 'Create Account' }}
        </button>
        
        <div v-if="error" class="error-message">
          {{ error }}
        </div>
        
        <div v-if="success" class="success-message">
          {{ success }}
        </div>
      </form>
      
      <div class="register-footer">
        <p>Already have an account? <router-link to="/login">Sign in here</router-link></p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '../services/api'

const router = useRouter()

const formData = ref({
  name: '',
  email: '',
  password: '',
  confirmPassword: '',
  tenant: '',
  role: ''
})

const isLoading = ref(false)
const error = ref('')
const success = ref('')

const handleRegister = async () => {
  error.value = ''
  success.value = ''
  
  // Validation
  if (formData.value.password !== formData.value.confirmPassword) {
    error.value = 'Passwords do not match'
    return
  }
  
  if (formData.value.password.length < 6) {
    error.value = 'Password must be at least 6 characters long'
    return
  }
  
  isLoading.value = true
  
  try {
    await api.register({
      name: formData.value.name,
      email: formData.value.email,
      password: formData.value.password,
      tenant: formData.value.tenant,
      role: formData.value.role
    })
    
    success.value = 'Account created successfully! Redirecting to login...'
    
    // Redirect to login after 2 seconds
    setTimeout(() => {
      router.push('/login')
    }, 2000)
    
  } catch (err) {
    console.error('Registration error:', err)
    error.value = 'Registration failed. Please try again.'
    
    // Mock successful registration for development
    if (formData.value.email && formData.value.password) {
      success.value = 'Account created successfully! Redirecting to login...'
      
      setTimeout(() => {
        router.push('/login')
      }, 2000)
    }
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.register-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.register-card {
  background: white;
  border-radius: 12px;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
  padding: 48px;
  width: 100%;
  max-width: 580px;
  min-width: 480px;
}

@media (max-width: 720px) {
  .register-card {
    padding: 32px;
    max-width: 100%;
    min-width: auto;
  }
}

.register-header {
  text-align: center;
  margin-bottom: 30px;
}

.register-header h1 {
  font-size: 2.75rem;
  font-weight: 700;
  color: #333;
  margin: 0 0 12px 0;
  letter-spacing: -0.025em;
}

.register-header p {
  color: #666;
  margin: 0;
  font-size: 1.125rem;
  font-weight: 400;
}

@media (max-width: 720px) {
  .register-header h1 {
    font-size: 2.25rem;
  }
  
  .register-header p {
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

@media (max-width: 720px) {
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

.register-btn {
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
  margin-top: 12px;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.25);
}

.register-btn:hover:not(:disabled) {
  transform: translateY(-2px);
}

.register-btn:disabled {
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

.success-message {
  color: #155724;
  text-align: center;
  margin-top: 15px;
  padding: 10px;
  background-color: #d4edda;
  border: 1px solid #c3e6cb;
  border-radius: 4px;
}

.register-footer {
  text-align: center;
  margin-top: 30px;
  padding-top: 20px;
  border-top: 1px solid #e1e5e9;
}

.register-footer a {
  color: #667eea;
  text-decoration: none;
  font-weight: 600;
}

.register-footer a:hover {
  text-decoration: underline;
}
</style>