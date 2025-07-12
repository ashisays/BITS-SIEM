<template>
  <div class="sources">
    <div class="container">
      <div class="sources-header">
        <h1>Security Sources</h1>
        <p class="sources-subtitle">Manage and monitor your security data sources</p>
        
        <div class="sources-actions">
          <button @click="showAddModal = true" class="btn-primary">
            <span class="icon">+</span>
            Add New Source
          </button>
          <button @click="refreshSources" class="btn-secondary" :disabled="loading">
            <span class="icon">🔄</span>
            Refresh
          </button>
        </div>
      </div>

      <div class="sources-content">
        <!-- Sources Grid -->
        <div class="sources-grid" v-if="sources.length > 0">
          <div v-for="source in sources" :key="source.id" class="source-card">
            <div class="source-header">
              <div class="source-info">
                <h3>{{ source.name }}</h3>
                <span class="source-type">{{ source.type }}</span>
              </div>
              <div class="source-status" :class="source.status">
                <span class="status-dot"></span>
                {{ source.status }}
              </div>
            </div>

            <div class="source-details">
              <div class="detail-item">
                <label>IP Address:</label>
                <span>{{ source.ip }}</span>
              </div>
              <div class="detail-item">
                <label>Port:</label>
                <span>{{ source.port }}</span>
              </div>
              <div class="detail-item">
                <label>Protocol:</label>
                <span>{{ source.protocol }}</span>
              </div>
              <div class="detail-item">
                <label>Last Activity:</label>
                <span>{{ formatDate(source.lastActivity) }}</span>
              </div>
            </div>

            <div class="source-notifications" v-if="source.notifications">
              <h4>📧 Email Notifications</h4>
              <div class="notification-emails">
                <span v-for="email in source.notifications.emails" :key="email" class="email-tag">
                  {{ email }}
                </span>
              </div>
              <div class="notification-settings">
                <label class="checkbox-label">
                  <input type="checkbox" :checked="source.notifications.enabled" @change="toggleNotifications(source)">
                  Enable email alerts
                </label>
              </div>
            </div>

            <div class="source-actions">
              <button @click="editSource(source)" class="btn-secondary">
                <span class="icon">✏️</span>
                Edit
              </button>
              <button @click="configureSource(source)" class="btn-secondary">
                <span class="icon">⚙️</span>
                Configure
              </button>
              <button @click="deleteSource(source)" class="btn-danger">
                <span class="icon">🗑️</span>
                Delete
              </button>
            </div>
          </div>
        </div>

        <!-- Empty State -->
        <div v-else class="empty-state">
          <div class="empty-icon">📡</div>
          <h3>No Sources Configured</h3>
          <p>Add your first security data source to start monitoring</p>
          <button @click="showAddModal = true" class="btn-primary">
            Add First Source
          </button>
        </div>
      </div>

      <!-- Add Source Modal -->
      <div v-if="showAddModal" class="modal-overlay" @click="closeModal">
        <div class="modal" @click.stop>
          <div class="modal-header">
            <h2>{{ editingSource ? 'Edit Source' : 'Add New Source' }}</h2>
            <button @click="closeModal" class="modal-close">×</button>
          </div>

          <form @submit.prevent="saveSource" class="modal-content">
            <div class="form-group">
              <label for="sourceName">Source Name</label>
              <input
                id="sourceName"
                v-model="sourceForm.name"
                type="text"
                required
                placeholder="e.g., Web Server Logs"
              >
            </div>

            <div class="form-group">
              <label for="sourceType">Source Type</label>
              <select id="sourceType" v-model="sourceForm.type" required>
                <option value="">Select type</option>
                <option value="syslog">Syslog</option>
                <option value="web-server">Web Server</option>
                <option value="database">Database</option>
                <option value="firewall">Firewall</option>
                <option value="ids">Intrusion Detection</option>
                <option value="antivirus">Antivirus</option>
              </select>
            </div>

            <div class="form-group">
              <label for="sourceIp">IP Address</label>
              <input
                id="sourceIp"
                v-model="sourceForm.ip"
                type="text"
                required
                placeholder="192.168.1.100"
              >
            </div>

            <div class="form-group">
              <label for="sourcePort">Port</label>
              <input
                id="sourcePort"
                v-model="sourceForm.port"
                type="number"
                required
                placeholder="514"
              >
            </div>

            <div class="form-group">
              <label for="sourceProtocol">Protocol</label>
              <select id="sourceProtocol" v-model="sourceForm.protocol" required>
                <option value="">Select protocol</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </select>
            </div>

            <div class="form-group">
              <label>📧 Email Notifications</label>
              <div class="email-inputs">
                <div v-for="(email, index) in sourceForm.notifications.emails" :key="index" class="email-input-row">
                  <input
                    v-model="sourceForm.notifications.emails[index]"
                    type="email"
                    placeholder="admin@company.com"
                  >
                  <button type="button" @click="removeEmail(index)" class="btn-remove">×</button>
                </div>
                <button type="button" @click="addEmail" class="btn-add-email">+ Add Email</button>
              </div>
              
              <label class="checkbox-label">
                <input type="checkbox" v-model="sourceForm.notifications.enabled">
                Enable email notifications for this source
              </label>
            </div>

            <div class="modal-actions">
              <button type="button" @click="closeModal" class="btn-secondary">Cancel</button>
              <button type="submit" class="btn-primary" :disabled="saving">
                {{ saving ? 'Saving...' : (editingSource ? 'Update' : 'Add Source') }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../services/api'

const sources = ref([])
const loading = ref(false)
const showAddModal = ref(false)
const editingSource = ref(null)
const saving = ref(false)

const sourceForm = ref({
  name: '',
  type: '',
  ip: '',
  port: '',
  protocol: '',
  notifications: {
    enabled: true,
    emails: ['']
  }
})

// Load sources on component mount
onMounted(() => {
  loadSources()
})

const loadSources = async () => {
  try {
    loading.value = true
    const data = await api.getSources()
    sources.value = data
  } catch (error) {
    console.error('Error loading sources:', error)
    // Mock data for development
    sources.value = [
      {
        id: 1,
        name: 'Web Server',
        type: 'web-server',
        ip: '192.168.1.100',
        port: 80,
        protocol: 'http',
        status: 'active',
        lastActivity: new Date().toISOString(),
        notifications: {
          enabled: true,
          emails: ['admin@acme.com', 'security@acme.com']
        }
      },
      {
        id: 2,
        name: 'Firewall',
        type: 'firewall',
        ip: '192.168.1.1',
        port: 514,
        protocol: 'udp',
        status: 'warning',
        lastActivity: new Date(Date.now() - 3600000).toISOString(),
        notifications: {
          enabled: true,
          emails: ['admin@acme.com']
        }
      }
    ]
  } finally {
    loading.value = false
  }
}

const refreshSources = () => {
  loadSources()
}

const editSource = (source) => {
  editingSource.value = source
  sourceForm.value = {
    ...source,
    notifications: {
      ...source.notifications,
      emails: [...source.notifications.emails]
    }
  }
  showAddModal.value = true
}

const deleteSource = async (source) => {
  if (confirm(`Are you sure you want to delete "${source.name}"?`)) {
    try {
      await api.deleteSource(source.id)
      sources.value = sources.value.filter(s => s.id !== source.id)
    } catch (error) {
      console.error('Error deleting source:', error)
      alert('Error deleting source')
    }
  }
}

const saveSource = async () => {
  try {
    saving.value = true
    
    if (editingSource.value) {
      // Update existing source
      const updatedSource = await api.updateSource(editingSource.value.id, sourceForm.value)
      const index = sources.value.findIndex(s => s.id === editingSource.value.id)
      sources.value[index] = updatedSource
    } else {
      // Add new source
      const newSource = await api.addSource(sourceForm.value)
      sources.value.push(newSource)
    }
    
    closeModal()
  } catch (error) {
    console.error('Error saving source:', error)
    alert('Error saving source')
  } finally {
    saving.value = false
  }
}

const configureSource = (source) => {
  // TODO: Implement advanced configuration modal
  alert(`Configure ${source.name} - Advanced settings coming soon!`)
}

const toggleNotifications = async (source) => {
  try {
    source.notifications.enabled = !source.notifications.enabled
    await api.updateSource(source.id, source)
  } catch (error) {
    console.error('Error updating notifications:', error)
    source.notifications.enabled = !source.notifications.enabled // Revert
  }
}

const addEmail = () => {
  sourceForm.value.notifications.emails.push('')
}

const removeEmail = (index) => {
  sourceForm.value.notifications.emails.splice(index, 1)
}

const closeModal = () => {
  showAddModal.value = false
  editingSource.value = null
  sourceForm.value = {
    name: '',
    type: '',
    ip: '',
    port: '',
    protocol: '',
    notifications: {
      enabled: true,
      emails: ['']
    }
  }
}

const formatDate = (dateStr) => {
  return new Date(dateStr).toLocaleString()
}
</script>

<style scoped>
.sources {
  min-height: calc(100vh - 72px);
  background-color: #f8f9fa;
}

.sources-header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 60px 0;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
}

.sources-header h1 {
  font-size: 3rem;
  font-weight: 700;
  margin: 0 0 12px 0;
  letter-spacing: -0.025em;
}

.sources-subtitle {
  font-size: 1.25rem;
  opacity: 0.9;
  margin: 0 0 32px 0;
  font-weight: 400;
}

.sources-actions {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.sources-content {
  padding: 48px 0;
}

.sources-grid {
  display: grid;
  gap: 32px;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  max-width: 1400px;
  margin: 0 auto;
}

.source-card {
  background: white;
  border-radius: 16px;
  padding: 32px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  border: 1px solid #e9ecef;
  transition: all 0.2s ease;
}

.source-card:hover {
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.12);
  transform: translateY(-2px);
}

.source-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}

.source-info h3 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0 0 8px 0;
  color: #333;
}

.source-type {
  background: #e9ecef;
  color: #495057;
  padding: 4px 12px;
  border-radius: 16px;
  font-size: 0.875rem;
  font-weight: 500;
  text-transform: capitalize;
}

.source-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 20px;
  font-size: 0.875rem;
  font-weight: 500;
  text-transform: capitalize;
}

.source-status.active {
  background: #d4edda;
  color: #155724;
}

.source-status.warning {
  background: #fff3cd;
  color: #856404;
}

.source-status.error {
  background: #f8d7da;
  color: #721c24;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: currentColor;
}

.source-details {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}

.detail-item {
  display: flex;
  flex-direction: column;
}

.detail-item label {
  font-size: 0.875rem;
  color: #666;
  margin-bottom: 4px;
  font-weight: 500;
}

.detail-item span {
  color: #333;
  font-weight: 500;
}

.source-notifications {
  background: #f8f9fa;
  padding: 20px;
  border-radius: 12px;
  margin-bottom: 24px;
}

.source-notifications h4 {
  margin: 0 0 12px 0;
  color: #333;
  font-size: 1rem;
}

.notification-emails {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.email-tag {
  background: #667eea;
  color: white;
  padding: 4px 12px;
  border-radius: 16px;
  font-size: 0.875rem;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.875rem;
  color: #666;
  cursor: pointer;
}

.source-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.empty-state {
  text-align: center;
  max-width: 400px;
  margin: 80px auto;
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: 24px;
}

.empty-state h3 {
  font-size: 1.5rem;
  color: #333;
  margin-bottom: 12px;
}

.empty-state p {
  color: #666;
  margin-bottom: 32px;
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
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal {
  background: white;
  border-radius: 12px;
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px 32px;
  border-bottom: 1px solid #e9ecef;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  color: #333;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  padding: 4px;
  color: #666;
}

.modal-content {
  padding: 32px;
}

.form-group {
  margin-bottom: 24px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
  color: #333;
  font-size: 0.95rem;
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 12px 16px;
  border: 2px solid #e1e5e9;
  border-radius: 8px;
  font-size: 16px;
  transition: all 0.2s ease;
  box-sizing: border-box;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.email-inputs {
  border: 1px solid #e1e5e9;
  border-radius: 8px;
  padding: 16px;
}

.email-input-row {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.email-input-row input {
  flex: 1;
  margin-bottom: 0;
}

.btn-remove {
  background: #dc3545;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 8px 12px;
  cursor: pointer;
  font-size: 14px;
}

.btn-add-email {
  background: #28a745;
  color: white;
  border: none;
  border-radius: 6px;
  padding: 8px 16px;
  cursor: pointer;
  font-size: 0.875rem;
}

.modal-actions {
  padding: 24px 32px;
  border-top: 1px solid #e9ecef;
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

/* Button Styles */
.btn-primary,
.btn-secondary,
.btn-danger {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border: none;
  border-radius: 8px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  text-decoration: none;
  font-size: 0.95rem;
}

.btn-primary {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.25);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.3);
}

.btn-secondary {
  background: #f8f9fa;
  color: #495057;
  border: 1px solid #e9ecef;
}

.btn-secondary:hover:not(:disabled) {
  background: #e9ecef;
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-primary:disabled,
.btn-secondary:disabled,
.btn-danger:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
}

.icon {
  font-size: 0.875rem;
}

@media (max-width: 768px) {
  .sources-header h1 {
    font-size: 2.25rem;
  }
  
  .sources-subtitle {
    font-size: 1.1rem;
  }
  
  .sources-content {
    padding: 32px 0;
  }
  
  .sources-grid {
    grid-template-columns: 1fr;
  }
  
  .source-card {
    padding: 24px;
  }
  
  .source-details {
    grid-template-columns: 1fr;
  }
  
  .modal {
    margin: 20px;
  }
  
  .modal-header,
  .modal-content,
  .modal-actions {
    padding: 20px;
  }
}
</style>
