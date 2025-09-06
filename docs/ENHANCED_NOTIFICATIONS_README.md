# Enhanced Notification System for BITS-SIEM

## Overview

The enhanced notification system provides comprehensive notification management capabilities for the BITS-SIEM platform, including admin controls, status management, and integration with the reports system.

## Features

### 🔐 Admin Controls
- **Suppress Notifications**: Admins can suppress false positive alerts
- **Status Management**: Full lifecycle management of security alerts
- **Organization-wide View**: All notifications for the organization are visible
- **Role-based Access**: Different permissions for admins vs regular users

### 📊 Status Management
- **Open**: New alerts requiring attention
- **Investigating**: Alerts under active investigation
- **Resolved**: Alerts that have been addressed
- **Suppressed**: Alerts suppressed by admin (false positives)
- **Safe**: Alerts marked as safe after investigation

### 🔄 Real-time Updates
- **WebSocket Integration**: Real-time notification delivery
- **Status Synchronization**: Changes reflect immediately across all components
- **Dashboard Integration**: Status changes update both notifications and reports pages

## API Endpoints

### Core Notification Endpoints

#### GET `/api/notifications`
Retrieves all notifications for the authenticated user's organization.

**Response:**
```json
[
  {
    "id": "alert_1",
    "message": "🚨 Security Alert: Brute Force Attack Detected",
    "timestamp": "2024-01-15T10:30:00Z",
    "tenant": "demo-org",
    "severity": "critical",
    "isRead": false,
    "status": "open",
    "metadata": {
      "alert_type": "brute_force",
      "source_ip": "192.168.1.100",
      "status": "open"
    },
    "type": "security_alert"
  }
]
```

#### GET `/api/notifications/stats`
Retrieves notification statistics for the organization.

**Response:**
```json
{
  "total_notifications": 15,
  "total_security_alerts": 8,
  "unread_count": 5,
  "unread_alerts": 3,
  "status_breakdown": {
    "open": 3,
    "investigating": 2,
    "resolved": 2,
    "suppressed": 1,
    "safe": 0
  },
  "severity_breakdown": {
    "critical": 2,
    "warning": 4,
    "info": 2
  }
}
```

### Status Management Endpoints

#### PATCH `/api/notifications/{notification_id}/status`
Updates the status of a notification.

**Request Body:**
```json
{
  "status": "investigating"
}
```

**Valid Statuses:**
- `open` - New alert requiring attention
- `investigating` - Under active investigation
- `resolved` - Issue has been addressed
- `suppressed` - Suppressed by admin (false positive)
- `safe` - Marked as safe after investigation

#### PATCH `/api/notifications/{notification_id}/investigate`
Marks a notification as under investigation.

#### PATCH `/api/notifications/{notification_id}/resolve`
Marks a notification as resolved.

#### PATCH `/api/notifications/{notification_id}/suppress`
Suppresses a notification (admin only).

#### PATCH `/api/notifications/{notification_id}/read`
Marks a notification as read.

### Management Endpoints

#### DELETE `/api/notifications/{notification_id}`
Deletes a notification (admin only for security alerts).

#### PATCH `/api/notifications/read-all`
Marks all notifications as read.

## Dashboard Components

### Notifications.vue
The main notifications component with enhanced features:

- **Filtering**: By severity, status, and type
- **Admin Controls**: Suppress, resolve, investigate buttons
- **Status Management**: Full lifecycle control
- **Real-time Updates**: WebSocket integration
- **Organization View**: All notifications for the tenant

### DiagnosisReports.vue
Enhanced reports component showing notification status:

- **Status Summary**: Visual breakdown of notification statuses
- **Integration**: Reflects notification status changes
- **Enhanced Security Reports**: Include notification management data

## Usage Examples

### Marking an Alert as Investigating
```javascript
// Frontend
await api.investigateNotification('alert_123')

// Backend automatically updates status
// Frontend reflects change immediately
```

### Suppressing a False Positive (Admin Only)
```javascript
// Only admins can suppress
if (store.isAdmin) {
  await api.suppressNotification('alert_456')
}
```

### Getting Organization-wide Stats
```javascript
const stats = await api.getNotificationStats()
console.log(`Open alerts: ${stats.status_breakdown.open}`)
```

## Security Features

### Role-based Access Control
- **Regular Users**: Can view, mark as read, resolve, investigate
- **Admins**: Can additionally suppress and delete notifications
- **Security Alerts**: Require admin privileges for deletion

### Tenant Isolation
- Users can only access notifications from their organization
- All API endpoints enforce tenant boundaries
- Status changes are scoped to the user's tenant

## Integration Points

### Reports System
- Notification status changes automatically reflect in reports
- Enhanced security reports include notification management data
- Status breakdowns show organization-wide notification health

### WebSocket System
- Real-time notification delivery
- Status changes broadcast to all connected clients
- Immediate UI updates across all components

### Detection System
- Security alerts automatically create notifications
- Status changes sync with detection system
- Correlation data preserved in notification metadata

## Configuration

### Environment Variables
```bash
# Notification system configuration
NOTIFICATION_ENABLED=true
NOTIFICATION_WEBHOOK_URL=https://webhook.example.com
NOTIFICATION_EMAIL_ENABLED=true
```

### Database Schema
The system uses the existing notification and security alert tables with added status fields:

```sql
-- Notifications table
CREATE TABLE notifications (
  id SERIAL PRIMARY KEY,
  tenant_id VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  severity VARCHAR(50),
  status VARCHAR(50) DEFAULT 'open',
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security alerts table
CREATE TABLE security_alerts (
  id SERIAL PRIMARY KEY,
  tenant_id VARCHAR(255) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  severity VARCHAR(50),
  status VARCHAR(50) DEFAULT 'open',
  alert_type VARCHAR(100),
  source_ip INET,
  username VARCHAR(255),
  confidence_score DECIMAL(3,2),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing

### Run the Test Suite
```bash
python test_enhanced_notifications.py
```

### Manual Testing
1. **Login** to the dashboard as admin
2. **Navigate** to the notifications page
3. **Test** status changes (investigate, resolve, suppress)
4. **Verify** changes reflect in reports page
5. **Check** admin-only controls are properly restricted

### Test Scenarios
- [ ] Regular user can view notifications
- [ ] Regular user can mark as read, investigate, resolve
- [ ] Regular user cannot suppress or delete security alerts
- [ ] Admin can perform all actions
- [ ] Status changes reflect in reports
- [ ] WebSocket updates work in real-time

## Troubleshooting

### Common Issues

#### Notifications Not Loading
- Check authentication token
- Verify tenant ID is set
- Check API endpoint availability

#### Status Changes Not Reflecting
- Verify database connection
- Check API response codes
- Ensure proper tenant isolation

#### Admin Controls Not Visible
- Verify user role is 'admin'
- Check store authentication state
- Refresh page after login

### Debug Mode
Enable debug logging in the browser console:
```javascript
localStorage.setItem('debug', 'true')
```

## Future Enhancements

### Planned Features
- **Bulk Operations**: Mass status updates
- **Notification Templates**: Customizable alert formats
- **Escalation Rules**: Automatic status progression
- **Integration APIs**: Third-party system integration
- **Advanced Filtering**: Saved filters and search queries

### Performance Optimizations
- **Pagination**: Large notification lists
- **Caching**: Frequently accessed data
- **Background Processing**: Async status updates
- **Database Indexing**: Optimized queries

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review API response codes
3. Check browser console for errors
4. Verify database connectivity
5. Test with the provided test suite

## Contributing

When adding new features:
1. Update API documentation
2. Add corresponding frontend components
3. Include proper error handling
4. Add test coverage
5. Update this README
