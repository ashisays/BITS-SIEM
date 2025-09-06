# 🚨 BITS-SIEM Dashboard Notifications Guide

## ✅ **SYSTEM STATUS: WORKING**

The enhanced BITS-SIEM system is fully operational with real-time notifications!

## 👤 **ADMIN CREDENTIALS**

### **Primary Demo Account (Recommended)**
- **Email**: `admin@demo.com`
- **Password**: `demo123`
- **Tenant**: `demo-org`
- **Access**: Full admin access to Demo Organization

### **Additional Dummy Organizations**
1. **Dummy Tech Solutions**
   - **Email**: `admin@dummytech.com`
   - **Password**: `admin123`
   - **Tenant**: `dummy-tech`

2. **Dummy Finance Corp**
   - **Email**: `admin@dummyfinance.com`
   - **Password**: `password123`
   - **Tenant**: `dummy-finance`

3. **Dummy Manufacturing Co**
   - **Email**: `admin@dummymanufacturing.com`
   - **Password**: `admin123`
   - **Tenant**: `dummy-manufacturing`

## 🌐 **ACCESS URLS**

- **Main Dashboard**: http://localhost:3000
- **Detection Dashboard**: http://localhost:3000/tenant/demo-org/dashboard
- **Notifications Page**: http://localhost:3000/tenant/demo-org/notifications
- **API**: http://localhost:8000
- **Notification Service**: http://localhost:8001

## 📱 **HOW TO SEE NOTIFICATIONS ON DASHBOARD**

### **Step 1: Access the Dashboard**
1. Open your browser to: http://localhost:3000
2. Login with: `admin@demo.com` / `demo123`

### **Step 2: Navigate to Detection Dashboard**
1. After login, you'll see the main dashboard
2. Click on "Detection Dashboard" or go to: http://localhost:3000/tenant/demo-org/dashboard
3. Look for the "Real-time ON/OFF" button in the top-right
4. Ensure it shows "Real-time ON" and "Connected" status

### **Step 3: Trigger Notifications**
Run this command to trigger a brute force attack:
```bash
python demo_dashboard_notifications.py
```

### **Step 4: Watch for Notifications**
You should see:
1. **Toast notifications** appearing in the top-right corner
2. **Real-time alert updates** in the alerts table
3. **Statistics updates** in the dashboard cards
4. **Desktop notifications** (if enabled)
5. **Sound alerts** (if enabled)

## 🔔 **NOTIFICATION TYPES**

### **Real-time Notifications**
- **Location**: Detection Dashboard (top-right corner)
- **Types**: Security alerts, brute force attacks, port scans
- **Format**: Colored toast notifications with severity indicators

### **Persistent Notifications**
- **Location**: Notifications page
- **Types**: All system notifications and alerts
- **Format**: Card-based list with filtering options

## 🧪 **TESTING COMMANDS**

### **Test WebSocket Notifications**
```bash
python test_dashboard_notifications.py
```

### **Trigger Brute Force Attack**
```bash
for i in {1..6}; do
  curl -X POST "http://localhost:8000/api/detection/events/ingest?tenant_id=demo-org" \
    -H "Content-Type: application/json" \
    -d '{"username": "testuser", "event_type": "login_failure", "source_type": "web", "source_ip": "192.168.1.200", "failed_attempts_count": '$i', "metadata": {"test": true}}'
  sleep 0.5
done
```

### **Send Direct Notification**
```bash
curl -X POST "http://localhost:8001/notifications/send" \
  -H "Content-Type: application/json" \
  -d '{"id": "test-123", "tenant_id": "demo-org", "user_id": "admin@demo.com", "type": "security_alert", "severity": "critical", "title": "Test Alert", "message": "This is a test alert", "source_ip": "192.168.1.100", "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}'
```

## 🔧 **TROUBLESHOOTING**

### **If Notifications Don't Appear:**

1. **Check WebSocket Connection**
   - Look for "Connected" status in Detection Dashboard
   - Check browser console for WebSocket errors

2. **Check Service Status**
   ```bash
   docker-compose -f docker-compose.enhanced.yml ps
   curl http://localhost:8001/health
   ```

3. **Check Logs**
   ```bash
   docker logs bits-siem-notification --tail 20
   ```

4. **Restart Services**
   ```bash
   docker-compose -f docker-compose.enhanced.yml restart notification
   ```

### **If Real-time Toggle Shows Disconnected:**
1. Refresh the page
2. Check if notification service is running on port 8001
3. Ensure you're logged in with correct credentials

## 🎯 **EXPECTED BEHAVIOR**

When you trigger a security event, you should see:

1. **Immediate toast notification** in top-right corner
2. **New alert** appearing in the alerts table
3. **Updated statistics** in the dashboard cards
4. **Connection status** showing "Connected"
5. **Alert details** when clicking on alerts

## 📊 **SYSTEM PERFORMANCE**

- **WebSocket Notifications**: ✅ Working
- **Authentication**: ✅ Working  
- **Alert Generation**: ✅ Working
- **Dashboard Integration**: ✅ Working
- **Real-time Updates**: ✅ Working

## 🚀 **SUCCESS INDICATORS**

✅ Services running on correct ports
✅ WebSocket connections established
✅ Notifications sent successfully
✅ Dashboard receives real-time updates
✅ Admin credentials working
✅ Dummy organizations configured

---

**Note**: The notifications appear on the **Detection Dashboard**, not the general notifications page. Make sure you're on the right page to see real-time security alerts!
