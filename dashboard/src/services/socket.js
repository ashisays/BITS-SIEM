let socket
let reconnectAttempts = 0
const maxReconnectAttempts = 5
const reconnectDelay = 2000

export function connectWebSocket(token, tenantId, onMessage, onConnect, onDisconnect) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.close()
  }

  try {
    // Connect to the enhanced notification service
    socket = new WebSocket(`ws://localhost:8001/ws/notifications/${tenantId}?token=${token}`)
    
    socket.onopen = (event) => {
      console.log('WebSocket connected to notification service')
      reconnectAttempts = 0
      if (onConnect) onConnect(event)
    }
    
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        console.log('Received notification:', data)
        
        // Handle different notification types
        if (data.type === 'security_alert') {
          // Show toast notification for security alerts
          showSecurityAlertToast(data)
        }
        
        // Call the main message handler
        if (onMessage) onMessage(data)
        
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }
    
    socket.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason)
      if (onDisconnect) onDisconnect(event)
      
      // Attempt to reconnect if not a normal closure
      if (event.code !== 1000 && reconnectAttempts < maxReconnectAttempts) {
        setTimeout(() => {
          reconnectAttempts++
          console.log(`Attempting to reconnect... (${reconnectAttempts}/${maxReconnectAttempts})`)
          connectWebSocket(token, tenantId, onMessage, onConnect, onDisconnect)
        }, reconnectDelay * reconnectAttempts)
      }
    }
    
    socket.onerror = (error) => {
      console.error('WebSocket error:', error)
    }
    
  } catch (error) {
    console.error('Failed to create WebSocket connection:', error)
  }
}

export function disconnectWebSocket() {
  if (socket) {
    socket.close(1000, 'Normal closure')
    socket = null
  }
}

export function isConnected() {
  return socket && socket.readyState === WebSocket.OPEN
}

// Show toast notification for security alerts
function showSecurityAlertToast(alert) {
  // Create toast element
  const toast = document.createElement('div')
  toast.className = 'security-alert-toast'
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${getSeverityColor(alert.severity)};
    color: white;
    padding: 16px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10000;
    max-width: 400px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    animation: slideInRight 0.3s ease-out;
  `
  
  // Set content based on alert type
  let icon = '🚨'
  let title = 'Security Alert'
  
  if (alert.type === 'brute_force_attack') {
    icon = '🔐'
    title = 'Brute Force Attack'
  } else if (alert.type === 'port_scan_attack') {
    icon = '🔍'
    title = 'Port Scan Detected'
  } else if (alert.type === 'anomaly_detected') {
    icon = '⚠️'
    title = 'Anomaly Detected'
  }
  
  toast.innerHTML = `
    <div style="display: flex; align-items: flex-start; gap: 12px;">
      <div style="font-size: 24px;">${icon}</div>
      <div style="flex: 1;">
        <div style="font-weight: 600; margin-bottom: 4px;">${title}</div>
        <div style="font-size: 14px; opacity: 0.9; margin-bottom: 8px;">${alert.title}</div>
        <div style="font-size: 13px; opacity: 0.8;">${alert.message}</div>
        ${alert.source_ip ? `<div style="font-size: 12px; opacity: 0.7; margin-top: 4px;">Source: ${alert.source_ip}</div>` : ''}
      </div>
      <button onclick="this.parentElement.parentElement.remove()" style="
        background: none; border: none; color: white; cursor: pointer; 
        font-size: 18px; opacity: 0.7; padding: 0; margin-left: 8px;
      ">&times;</button>
    </div>
  `
  
  // Add CSS animation
  const style = document.createElement('style')
  style.textContent = `
    @keyframes slideInRight {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  `
  document.head.appendChild(style)
  
  // Add to page
  document.body.appendChild(toast)
  
  // Auto-remove after 8 seconds
  setTimeout(() => {
    if (toast.parentElement) {
      toast.style.animation = 'slideOutRight 0.3s ease-in'
      setTimeout(() => {
        if (toast.parentElement) {
          toast.remove()
        }
      }, 300)
    }
  }, 8000)
  
  // Add slide out animation
  const slideOutStyle = document.createElement('style')
  slideOutStyle.textContent = `
    @keyframes slideOutRight {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }
  `
  document.head.appendChild(slideOutStyle)
}

// Get color based on severity
function getSeverityColor(severity) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '#dc3545'
    case 'high':
      return '#fd7e14'
    case 'medium':
      return '#ffc107'
    case 'low':
      return '#28a745'
    default:
      return '#6c757d'
  }
}

// Export utility functions
export const socketUtils = {
  connect: connectWebSocket,
  disconnect: disconnectWebSocket,
  isConnected,
  showSecurityAlertToast
} 