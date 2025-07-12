<template>
  <div class="diagnosis-reports">
    <h2>Diagnosis Reports</h2>
    <ul>
      <li v-for="report in reports" :key="report.id">
        <strong>{{ report.title }}</strong>: {{ report.summary }}
      </li>
    </ul>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../services/api'

const reports = ref([])

const fetchReports = async () => {
  const res = await api.getReports()
  reports.value = res.data
}

onMounted(fetchReports)
</script> 