import axios from 'axios'

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
})

api.interceptors.request.use(config => {
  const token = localStorage.getItem('jwt')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export default {
  register(data) {
    return api.post('/register', data)
  },
  login(data) {
    return api.post('/login', data)
  },
  getSources() {
    return api.get('/sources')
  },
  addSource(source) {
    return api.post('/sources', source)
  },
  deleteSource(id) {
    return api.delete(`/sources/${id}`)
  },
  getNotifications() {
    return api.get('/notifications')
  },
  getReports() {
    return api.get('/reports')
  }
} 