<template>
  <div class="source-config">
    <h2>Syslog Sources</h2>
    <form @submit.prevent="addSource">
      <input v-model="sourceIp" type="text" placeholder="Source IP/Network" required />
      <button type="submit">Add Source</button>
    </form>
    <ul>
      <li v-for="source in sources" :key="source.id">
        {{ source.ip }} <button @click="deleteSource(source.id)">Delete</button>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../services/api'

const sources = ref([])
const sourceIp = ref('')

const fetchSources = async () => {
  const res = await api.getSources()
  sources.value = res.data
}

const addSource = async () => {
  await api.addSource({ ip: sourceIp.value })
  sourceIp.value = ''
  fetchSources()
}

const deleteSource = async (id) => {
  await api.deleteSource(id)
  fetchSources()
}

onMounted(fetchSources)
</script> 