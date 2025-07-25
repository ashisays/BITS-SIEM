<script setup>
import { onMounted } from 'vue'
import NavBar from './components/NavBar.vue'
import { useAuth } from './composables/useAuth'

const { initializeAuth, checkSessionExpiry } = useAuth()

// Initialize authentication on app startup
onMounted(() => {
  initializeAuth()
  checkSessionExpiry()
})
</script>

<template>
  <div id="app">
    <NavBar />
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html {
  font-size: 16px;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
  line-height: 1.6;
  color: #333;
  background-color: #f8f9fa;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

#app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* Global button styles */
.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  text-decoration: none;
  display: inline-block;
  transition: all 0.2s ease;
}

.btn-primary {
  background-color: #007bff;
  color: white;
}

.btn-primary:hover {
  background-color: #0056b3;
}

.btn-secondary {
  background-color: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background-color: #545b62;
}

.btn-outline {
  background-color: transparent;
  border: 1px solid #007bff;
  color: #007bff;
}

.btn-outline:hover {
  background-color: #007bff;
  color: white;
}

.btn-warning {
  background-color: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background-color: #e0a800;
}

.btn-danger {
  background-color: #dc3545;
  color: white;
}

.btn-danger:hover {
  background-color: #c82333;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

/* Utility classes */
.container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 24px;
}

@media (max-width: 768px) {
  .container {
    padding: 0 20px;
  }
}

@media (max-width: 640px) {
  .container {
    padding: 0 16px;
  }
}

.text-center {
  text-align: center;
}

.mt-2 { margin-top: 0.5rem; }
.mt-3 { margin-top: 1rem; }
.mt-4 { margin-top: 1.5rem; }
.mb-2 { margin-bottom: 0.5rem; }
.mb-3 { margin-bottom: 1rem; }
.mb-4 { margin-bottom: 1.5rem; }

/* Main content layout */
.main-content {
  flex: 1;
  min-height: calc(100vh - 72px); /* Subtract navbar height */
  background-color: #f8f9fa;
  width: 100%;
}

@media (max-width: 768px) {
  .main-content {
    min-height: calc(100vh - 64px);
  }
}

/* Override for login/register pages */
.main-content:has(.login-container),
.main-content:has(.register-container) {
  min-height: 100vh;
  background: transparent;
  flex: 1;
}
</style>
