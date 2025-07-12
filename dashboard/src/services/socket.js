let socket

export function connectWebSocket(token, onMessage) {
  socket = new WebSocket(`ws://localhost:8000/ws/notifications?token=${token}`)
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data)
    onMessage(data)
  }
}

export function disconnectWebSocket() {
  if (socket) socket.close()
} 