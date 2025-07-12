<template>
  <div class="notifications">
    <h2>Notifications</h2>
    <ul>
      <li v-for="notification in notifications" :key="notification.id">
        {{ notification.message }} <span>({{ notification.timestamp }})</span>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useMainStore } from '../store'
import { connectWebSocket, disconnectWebSocket } from '../services/socket'
import api from '../services/api'

const store = useMainStore()

const fetchNotifications = async () => {
  const res = await api.getNotifications()
  store.setNotifications(res.data)
}

onMounted(() => {
  fetchNotifications()
  connectWebSocket(store.jwt, (data) => {
    store.addNotification(data)
  })
})
</script> 