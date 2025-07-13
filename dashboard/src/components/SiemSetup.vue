<template>
  <div class="siem-setup">
    <div class="setup-header">
      <h2>SIEM Setup Configuration</h2>
      <p>Configure your SIEM server settings and get setup instructions for your devices.</p>
    </div>

    <!-- Configuration Form -->
    <div class="config-section">
      <h3>SIEM Server Configuration</h3>
      <form class="config-form">
        <div class="form-row">
          <div class="form-group">
            <label>SIEM Server IP Address</label>
            <input :value="config.siem_server_ip" type="text" readonly />
          </div>
          <div class="form-group">
            <label>SIEM Server Port</label>
            <input :value="config.siem_server_port" type="number" readonly />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Protocol</label>
            <div class="protocol-checkboxes">
              <label><input type="checkbox" value="udp" v-model="selectedProtocols" @change="onProtocolChange" /> UDP</label>
              <label><input type="checkbox" value="tcp" v-model="selectedProtocols" @change="onProtocolChange" /> TCP</label>
              <label><input type="checkbox" value="tls" v-model="selectedProtocols" @change="onProtocolChange" /> TLS</label>
            </div>
          </div>
          <div class="form-group">
            <label for="syslog_format">Syslog Format</label>
            <select id="syslog_format" v-model="selectedSyslogFormat" @change="onSyslogFormatChange" required>
              <option value="rfc3164">RFC 3164 (Traditional)</option>
              <option value="rfc5424">RFC 5424 (Modern)</option>
              <option value="cisco">Cisco</option>
            </select>
          </div>
        </div>
        <div class="form-group checkbox-group">
          <label>
            <input type="checkbox" v-model="enableSyslog" />
            Enable Syslog
          </label>
        </div>
      </form>
    </div>

    <!-- Configuration Summary -->
    <div class="config-summary" v-if="config.siem_server_ip">
      <h3>Your SIEM Configuration</h3>
      <div class="summary-card">
        <div class="summary-item">
          <strong>Server:</strong> {{ config.siem_server_ip }}:{{ config.siem_server_port }}
        </div>
        <div class="summary-item">
          <strong>Protocol:</strong> {{ config.siem_protocol.toUpperCase() }}
        </div>
        <div class="summary-item">
          <strong>Format:</strong> {{ config.syslog_format.toUpperCase() }}
        </div>
        <div class="summary-item">
          <strong>Status:</strong> 
          <span :class="config.enabled ? 'status-active' : 'status-inactive'">
            {{ config.enabled ? 'Active' : 'Inactive' }}
          </span>
        </div>
      </div>
    </div>

    <!-- Setup Guide -->
    <div class="setup-guide" v-if="setupGuide">
      <h3>Setup Guide</h3>
      
      <div class="guide-steps">
        <div v-for="step in setupGuide.setup_steps" :key="step.step" class="guide-step">
          <div class="step-header">
            <span class="step-number">{{ step.step }}</span>
            <h4>{{ step.title }}</h4>
          </div>
          <p>{{ step.description }}</p>
          
          <div v-if="step.examples" class="step-examples">
            <h5>Configuration Examples:</h5>
            <div class="code-examples">
              <div v-for="(example, device) in step.examples" :key="device" class="code-example">
                <strong>{{ device.replace('_', ' ').toUpperCase() }}:</strong>
                <code>{{ example }}</code>
              </div>
            </div>
          </div>
          
          <div v-if="step.commands" class="step-commands">
            <h5>Test Commands:</h5>
            <div class="command-list">
              <div v-for="command in step.commands" :key="command" class="command">
                <code>{{ command }}</code>
              </div>
            </div>
          </div>
          
          <div v-if="step.actions" class="step-actions">
            <h5>Actions:</h5>
            <ul>
              <li v-for="action in step.actions" :key="action">{{ action }}</li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Supported Formats -->
      <div class="supported-formats">
        <h4>Supported Syslog Formats</h4>
        <div class="format-cards">
          <div v-for="format in setupGuide.supported_formats" :key="format.name" class="format-card">
            <h5>{{ format.name }}</h5>
            <p>{{ format.description }}</p>
            <div class="format-example">
              <strong>Example:</strong>
              <code>{{ format.example }}</code>
            </div>
          </div>
        </div>
      </div>

      <!-- Troubleshooting -->
      <div class="troubleshooting">
        <h4>Troubleshooting</h4>
        <div class="trouble-cards">
          <div v-for="trouble in setupGuide.troubleshooting" :key="trouble.issue" class="trouble-card">
            <h5>{{ trouble.issue }}</h5>
            <ul>
              <li v-for="solution in trouble.solutions" :key="solution">{{ solution }}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Loading and Error States -->
    <div v-if="loading" class="loading">
      <p>Loading configuration...</p>
    </div>
    
    <div v-if="error" class="error">
      <p>{{ error }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../services/api'

const config = ref({
  siem_server_ip: '',
  siem_server_port: 514,
  siem_protocol: 'udp',
  syslog_format: 'rfc3164',
  facility: 'local0',
  severity: 'info',
  enabled: true,
  setup_instructions: ''
})
const selectedSyslogFormat = ref('rfc3164')
const selectedProtocols = ref(['udp'])
const enableSyslog = ref(true)
const setupGuide = ref(null)
const loading = ref(false)
const error = ref('')

const loadConfig = async (format = null, protocol = null) => {
  loading.value = true
  error.value = ''
  try {
    const configData = await api.getTenantConfig(format, protocol)
    config.value = {
      siem_server_ip: configData.siem_server_ip,
      siem_server_port: configData.siem_server_port,
      siem_protocol: configData.siem_protocol,
      syslog_format: configData.syslog_format,
      facility: configData.facility,
      severity: configData.severity,
      enabled: configData.enabled,
      setup_instructions: configData.setup_instructions || ''
    }
    selectedSyslogFormat.value = configData.syslog_format
    selectedProtocols.value = [configData.siem_protocol]
    enableSyslog.value = configData.enabled
    setupGuide.value = await api.getSetupGuide()
  } catch (err) {
    error.value = 'Failed to load configuration: ' + err.message
  } finally {
    loading.value = false
  }
}

const onSyslogFormatChange = () => {
  loadConfig(selectedSyslogFormat.value, selectedProtocols.value[0])
}
const onProtocolChange = () => {
  // Only allow one protocol at a time for backend compatibility
  if (selectedProtocols.value.length > 1) {
    selectedProtocols.value = [selectedProtocols.value[selectedProtocols.value.length - 1]]
  }
  loadConfig(selectedSyslogFormat.value, selectedProtocols.value[0])
}
onMounted(() => loadConfig())
</script>

<style scoped>
.siem-setup {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.setup-header {
  text-align: center;
  margin-bottom: 30px;
}

.setup-header h2 {
  color: #2c3e50;
  margin-bottom: 10px;
}

.setup-header p {
  color: #7f8c8d;
  font-size: 16px;
}

.config-section {
  background: #fff;
  border-radius: 8px;
  padding: 25px;
  margin-bottom: 30px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.config-section h3 {
  color: #2c3e50;
  margin-bottom: 20px;
  border-bottom: 2px solid #3498db;
  padding-bottom: 10px;
}

.config-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
}

.form-group label {
  font-weight: 600;
  margin-bottom: 8px;
  color: #2c3e50;
}

.form-group input,
.form-group select,
.form-group textarea {
  padding: 12px;
  border: 2px solid #e0e0e0;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.3s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #3498db;
}

.checkbox-group {
  flex-direction: row;
  align-items: center;
  gap: 10px;
}

.checkbox-group input[type="checkbox"] {
  width: 18px;
  height: 18px;
}

.form-actions {
  display: flex;
  gap: 15px;
  justify-content: flex-start;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
}

.btn-primary:disabled {
  background: #bdc3c7;
  cursor: not-allowed;
}

.btn-secondary {
  background: #95a5a6;
  color: white;
}

.btn-secondary:hover {
  background: #7f8c8d;
}

.config-summary {
  background: #fff;
  border-radius: 8px;
  padding: 25px;
  margin-bottom: 30px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.summary-card {
  background: #f8f9fa;
  border-radius: 6px;
  padding: 20px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
}

.summary-item {
  font-size: 14px;
}

.status-active {
  color: #27ae60;
  font-weight: 600;
}

.status-inactive {
  color: #e74c3c;
  font-weight: 600;
}

.setup-guide {
  background: #fff;
  border-radius: 8px;
  padding: 25px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.guide-steps {
  display: flex;
  flex-direction: column;
  gap: 30px;
}

.guide-step {
  border-left: 4px solid #3498db;
  padding-left: 20px;
}

.step-header {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 15px;
}

.step-number {
  background: #3498db;
  color: white;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 14px;
}

.step-header h4 {
  margin: 0;
  color: #2c3e50;
}

.step-examples,
.step-commands,
.step-actions {
  margin-top: 15px;
}

.step-examples h5,
.step-commands h5,
.step-actions h5 {
  color: #34495e;
  margin-bottom: 10px;
}

.code-examples {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.code-example {
  background: #f8f9fa;
  padding: 12px;
  border-radius: 6px;
  border-left: 4px solid #3498db;
}

.code-example code {
  display: block;
  margin-top: 5px;
  font-family: 'Courier New', monospace;
  background: #2c3e50;
  color: #ecf0f1;
  padding: 8px;
  border-radius: 4px;
  font-size: 12px;
}

.command-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.command {
  background: #2c3e50;
  color: #ecf0f1;
  padding: 10px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
}

.step-actions ul {
  margin: 0;
  padding-left: 20px;
}

.step-actions li {
  margin-bottom: 5px;
  color: #34495e;
}

.supported-formats,
.troubleshooting {
  margin-top: 40px;
}

.supported-formats h4,
.troubleshooting h4 {
  color: #2c3e50;
  margin-bottom: 20px;
  border-bottom: 2px solid #3498db;
  padding-bottom: 10px;
}

.format-cards,
.trouble-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.format-card,
.trouble-card {
  background: #f8f9fa;
  border-radius: 6px;
  padding: 20px;
  border-left: 4px solid #3498db;
}

.format-card h5,
.trouble-card h5 {
  color: #2c3e50;
  margin-bottom: 10px;
}

.format-example {
  margin-top: 15px;
}

.format-example code {
  display: block;
  background: #2c3e50;
  color: #ecf0f1;
  padding: 10px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  margin-top: 5px;
}

.trouble-card ul {
  margin: 0;
  padding-left: 20px;
}

.trouble-card li {
  margin-bottom: 5px;
  color: #34495e;
}

.loading,
.error {
  text-align: center;
  padding: 40px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.error {
  color: #e74c3c;
}

@media (max-width: 768px) {
  .form-row {
    grid-template-columns: 1fr;
  }
  
  .summary-card {
    grid-template-columns: 1fr;
  }
  
  .format-cards,
  .trouble-cards {
    grid-template-columns: 1fr;
  }
  
  .form-actions {
    flex-direction: column;
  }
}
</style> 