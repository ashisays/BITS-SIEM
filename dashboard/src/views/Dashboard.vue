<template>
  <div class="dashboard">
    <h1>Tenant Dashboard</h1>
    <SourceConfig />
    <Notifications />
    <DiagnosisReports />
  </div>
</template>

<script setup>
import SourceConfig from '../components/SourceConfig.vue'
import Notifications from '../components/Notifications.vue'
import DiagnosisReports from '../components/DiagnosisReports.vue'
</script> 