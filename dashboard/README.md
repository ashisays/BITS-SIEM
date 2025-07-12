# BITS-SIEM Dashboard - Multi-Tenant Security Information and Event Management

[![Vue.js](https://img.shields.io/badge/Vue.js-3.5.17-4FC08D?logo=vue.js)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-7.0.0-646CFF?logo=vite)](https://vitejs.dev/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker)](https://docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive, multi-tenant Security Information and Event Management (SIEM) dashboard built with Vue.js 3, featuring advanced authentication, session management, and tenant isolation.

## 🚀 Key Features

### 🏢 **Multi-Tenancy Support**
- **Tenant-specific routing**: Isolated dashboards per organization
- **Tenant switching**: Users can switch between accessible tenants
- **Tenant administration**: Full tenant lifecycle management
- **Access control**: Role-based tenant access restrictions

### 🔐 **Advanced Authentication & Session Management**
- **JWT-based authentication** with secure token handling
- **Session persistence** across browser tabs and page refreshes
- **Auto-logout** with 30-minute inactivity timeout
- **Activity tracking** with automatic session renewal
- **Secure token storage** with error handling

### 🧭 **Comprehensive Navigation System**
- **Responsive navigation bar** with mobile hamburger menu
- **User avatar dropdown** with profile and logout options
- **Tenant context switching** from navigation
- **Role-based menu items** (Admin vs User access)
- **Active page highlighting** for better UX

### 👥 **User & Role Management**
- **Multi-role support**: Admin, Security Analyst, User roles
- **User administration panel** for tenant and user management
- **Registration system** with organization affiliation
- **Profile management** with role-based permissions

### 🔒 **Security Features**
- **Tenant isolation**: Complete data separation between tenants
- **Route guards**: Authentication and authorization checks
- **Session security**: Automatic cleanup and secure logout
- **CSRF protection**: Secure API communication

### 📊 **Dashboard & Monitoring**
- **Real-time statistics**: Event counts, active sources, alerts
- **Source configuration**: IP/network monitoring setup
- **Notification system**: Real-time alerts via WebSocket
- **Threat reports**: Security analysis and diagnostics
- **Responsive design**: Mobile-first approach

## 🏗️ Architecture

### **URL Structure**
```
# Public Routes
/                     → Redirects to /login
/login               → Authentication page
/register            → User registration

# Tenant-Specific Routes
/tenant/:tenantId/dashboard      → Tenant dashboard
/tenant/:tenantId/sources        → Source configuration
/tenant/:tenantId/notifications  → Notifications center
/tenant/:tenantId/reports        → Security reports

# Admin Routes (Role-based)
/admin/tenants       → Tenant management
/admin/users         → User management

# Legacy Routes (Auto-redirect)
/dashboard           → /tenant/{currentTenant}/dashboard
/sources             → /tenant/{currentTenant}/sources
/notifications       → /tenant/{currentTenant}/notifications
/reports             → /tenant/{currentTenant}/reports
```

### **Project Structure**
```
src/
├── components/           # Reusable UI components
│   ├── Login.vue        # Authentication component
│   ├── Register.vue     # User registration
│   ├── NavBar.vue       # Navigation bar
│   ├── AdminTenants.vue # Tenant management
│   ├── AdminUsers.vue   # User management
│   ├── SourceConfig.vue # Source configuration
│   ├── Notifications.vue# Notification system
│   └── DiagnosisReports.vue # Security reports
├── views/               # Page-level components
│   └── Dashboard.vue    # Main dashboard view
├── router/              # Vue Router configuration
│   └── index.js         # Multi-tenant routing setup
├── composables/         # Vue 3 composables
│   └── useAuth.js       # Authentication state management
├── services/            # API and external services
│   ├── api.js           # HTTP API client
│   └── socket.js        # WebSocket client
└── assets/              # Static assets
```

## 🛠️ Technology Stack

- **Frontend Framework**: Vue.js 3.5.17 with Composition API
- **Build Tool**: Vite 7.0.0 for fast development and builds
- **Routing**: Vue Router 4.3.0 with navigation guards
- **State Management**: Pinia 2.1.7 for reactive state
- **HTTP Client**: Native Fetch API (no external dependencies)
- **WebSocket**: Native WebSocket API for real-time features
- **Containerization**: Docker with Nginx for production
- **CSS**: Scoped CSS with responsive design

## 🚀 Quick Start

### **Prerequisites**
- Node.js 18+ (recommended: 20+)
- npm or yarn package manager
- Docker (optional, for containerized deployment)

### **Development Setup**

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd BITS-SIEM/dashboard
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start development server**
   ```bash
   npm run dev
   ```
   
   The application will be available at `http://localhost:5173`

4. **Build for production**
   ```bash
   npm run build
   ```

### **Docker Deployment**

1. **Build Docker image**
   ```bash
   docker build -t bits-siem-dashboard .
   ```

2. **Run container**
   ```bash
   docker run -p 3000:80 bits-siem-dashboard
   ```

3. **Using Docker Compose** (from parent directory)
   ```bash
   docker-compose up --build dashboard
   ```

## 🔧 Configuration

### **Environment Variables**
```bash
# API Configuration
VITE_API_BASE_URL=http://localhost:8000/api
VITE_WS_URL=ws://localhost:8000/ws

# Session Configuration
VITE_SESSION_TIMEOUT=1800000  # 30 minutes in milliseconds

# Development
VITE_MOCK_AUTH=true  # Enable mock authentication
```

### **Nginx Configuration**
The application includes a custom `nginx.conf` for Single Page Application (SPA) routing:
- Serves static assets with caching
- Handles client-side routing with fallback to `index.html`
- Includes security headers
- API proxy configuration (when backend is available)

## 👤 User Roles & Permissions

| Role | Dashboard | Sources | Notifications | Reports | Admin Panel |
|------|-----------|---------|---------------|---------|-------------|
| **Admin** | ✅ All Tenants | ✅ All Tenants | ✅ All Tenants | ✅ All Tenants | ✅ Full Access |
| **Security Analyst** | ✅ Own Tenant | ✅ Own Tenant | ✅ Own Tenant | ✅ Own Tenant | ❌ No Access |
| **User** | ✅ Own Tenant | ❌ Read-only | ✅ Own Tenant | ✅ Read-only | ❌ No Access |

## 🔐 Authentication Flow

1. **User Registration**
   - Complete registration form with organization details
   - Account verification (email/admin approval)
   - Role assignment by admin

2. **Login Process**
   - Email/password authentication
   - Tenant selection (if user has access to multiple tenants)
   - JWT token generation and storage
   - Redirect to tenant-specific dashboard

3. **Session Management**
   - Activity-based session renewal
   - 30-minute inactivity timeout
   - Secure token storage in localStorage
   - Automatic cleanup on logout

## 🧪 Testing Credentials

### **Demo Admin User**
- **Email**: `admin@demo.com`
- **Password**: `admin123`
- **Tenant**: `acme-corp`
- **Access**: Full admin privileges

### **Demo Regular User**
- **Email**: `user@demo.com`
- **Password**: `user123`
- **Tenant**: `beta-industries`
- **Access**: Standard user privileges

## 🎨 UI/UX Features

- **Responsive Design**: Mobile-first approach with breakpoints
- **Dark/Light Mode**: Professional SIEM dashboard styling
- **Accessibility**: ARIA labels and keyboard navigation
- **Loading States**: Smooth user experience with loading indicators
- **Error Handling**: User-friendly error messages and recovery
- **Toast Notifications**: Real-time feedback for user actions

## 🔌 API Integration

The dashboard is designed to work with a RESTful backend API:

### **Authentication Endpoints**
- `POST /api/auth/login` - User authentication
- `POST /api/auth/register` - User registration
- `GET /api/auth/tenants` - Get user's accessible tenants

### **Tenant Management**
- `GET /api/admin/tenants` - List all tenants
- `POST /api/admin/tenants` - Create new tenant
- `PUT /api/admin/tenants/:id` - Update tenant
- `DELETE /api/admin/tenants/:id` - Delete tenant

### **User Management**
- `GET /api/admin/users` - List users
- `POST /api/admin/users` - Create user
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user

### **SIEM Features**
- `GET /api/sources` - Get configured sources
- `POST /api/sources` - Add new source
- `GET /api/notifications` - Get notifications
- `GET /api/reports` - Get security reports

## 🚦 Development Guidelines

### **Code Style**
- Use Vue 3 Composition API
- Implement TypeScript for type safety (future enhancement)
- Follow Vue.js style guide
- Use ESLint and Prettier for code formatting

### **Component Structure**
```vue
<template>
  <!-- Template with semantic HTML -->
</template>

<script setup>
// Composition API with reactive references
// Import composables and utilities
// Define component logic
</script>

<style scoped>
/* Scoped styles with CSS variables */
/* Responsive design with media queries */
</style>
```

### **State Management**
- Use `useAuth` composable for authentication state
- Implement Pinia stores for complex state management
- Prefer composition API over options API

## 🐛 Troubleshooting

### **Common Issues**

1. **Login Page Not Loading**
   - Check if Vite dev server is running
   - Verify router configuration in `src/router/index.js`
   - Check browser console for JavaScript errors

2. **Session Not Persisting**
   - Clear localStorage and try again
   - Check if `useAuth` composable is properly imported
   - Verify JWT token format and expiration

3. **Navigation Not Working**
   - Ensure Vue Router is properly configured
   - Check route guards for authentication issues
   - Verify tenant access permissions

4. **Docker Build Failures**
   - Check Node.js version compatibility
   - Verify all dependencies are properly installed
   - Review nginx configuration for syntax errors

### **Debug Mode**
Enable debug logging by setting:
```javascript
localStorage.setItem('debug', 'true')
```

## 📈 Performance Optimizations

- **Code Splitting**: Lazy-loaded routes and components
- **Asset Optimization**: Minified CSS and JavaScript
- **Caching Strategy**: Static asset caching with Nginx
- **Bundle Analysis**: Use `npm run build -- --analyze`
- **Tree Shaking**: Eliminates unused code in production builds

## 🔮 Future Enhancements

- [ ] TypeScript integration for better type safety
- [ ] Dark mode theme support
- [ ] Advanced charts and visualizations
- [ ] Real-time collaboration features
- [ ] Mobile app support
- [ ] Advanced security analytics
- [ ] Integration with external SIEM tools
- [ ] Multi-language support (i18n)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the troubleshooting section above

---

**Built with ❤️ for cybersecurity professionals**

---
