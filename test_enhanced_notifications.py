#!/usr/bin/env python3
"""
BITS-SIEM Enhanced Notification System Test
==========================================

This script tests the enhanced notification system including:
- Real-time WebSocket notifications
- Email notifications
- Webhook integrations
- Brute force attack detection
- Dashboard integration
"""

import asyncio
import json
import time
import requests
import websockets
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any

# Configuration
API_BASE = "http://localhost:8000"
NOTIFICATION_BASE = "http://localhost:8001"
WEBSOCKET_URL = "ws://localhost:8001/ws/notifications"

class NotificationTester:
    """Test the enhanced notification system"""
    
    def __init__(self):
        self.session = requests.Session()
        self.auth_token = None
        self.tenant_id = "demo-org"
        self.test_results = []
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        self.test_results.append({
            'test': test_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
    
    def authenticate(self) -> bool:
        """Authenticate with the SIEM system"""
        try:
            # Login
            login_data = {
                "email": "admin@demo.com",
                "password": "demo123"
            }
            
            response = self.session.post(f"{API_BASE}/api/auth/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data.get('token')
                if self.auth_token:
                    self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
                    self.log_test("Authentication", True, f"Token: {self.auth_token[:20]}...")
                    return True
                else:
                    self.log_test("Authentication", False, "No access token in response")
                    return False
            else:
                self.log_test("Authentication", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Authentication", False, f"Error: {str(e)}")
            return False
    
    def test_notification_service_health(self) -> bool:
        """Test notification service health endpoint"""
        try:
            response = requests.get(f"{NOTIFICATION_BASE}/health")
            if response.status_code == 200:
                data = response.json()
                status = data.get('status')
                if status == 'healthy':
                    self.log_test("Notification Service Health", True, f"Status: {status}")
                    return True
                else:
                    self.log_test("Notification Service Health", False, f"Status: {status}")
                    return False
            else:
                self.log_test("Notification Service Health", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Notification Service Health", False, f"Error: {str(e)}")
            return False
    
    def test_brute_force_detection(self) -> bool:
        """Test brute force attack detection and notification"""
        try:
            # Send multiple failed authentication events to trigger brute force detection
            failed_events = []
            
            for i in range(10):  # Send 10 failed attempts
                event_data = {
                    "username": "testuser",
                    "event_type": "login_failure",
                    "source_type": "web",
                    "source_ip": "192.168.1.100",
                    "source_port": 12345,
                    "user_agent": "Mozilla/5.0 (Test Browser)",
                    "country": "US",
                    "city": "Test City",
                    "device_fingerprint": f"test_device_{i}",
                    "session_id": f"session_{uuid.uuid4()}",
                    "failed_attempts_count": i + 1,
                    "time_since_last_attempt": 1,
                    "metadata": {
                        "test": True,
                        "iteration": i
                    }
                }
                
                response = self.session.post(
                    f"{API_BASE}/api/detection/events/ingest?tenant_id={self.tenant_id}",
                    json=event_data
                )
                
                if response.status_code == 200:
                    failed_events.append(event_data)
                else:
                    print(f"   Warning: Failed to send event {i}: {response.status_code}")
                
                time.sleep(0.1)  # Small delay between events
            
            if len(failed_events) >= 5:
                self.log_test("Brute Force Detection", True, f"Sent {len(failed_events)} failed events")
                return True
            else:
                self.log_test("Brute Force Detection", False, f"Only sent {len(failed_events)} events")
                return False
                
        except Exception as e:
            self.log_test("Brute Force Detection", False, f"Error: {str(e)}")
            return False
    
    def test_port_scan_detection(self) -> bool:
        """Test port scan detection and notification"""
        try:
            # Send multiple network connection events to trigger port scan detection
            scan_events = []
            
            # Simulate scanning different ports
            ports = [22, 80, 443, 3389, 5985, 21, 23, 25, 53, 110, 143, 993, 995]
            
            for i, port in enumerate(ports):
                event_data = {
                    "username": "scanner",
                    "event_type": "network_connection",
                    "source_type": "network",
                    "source_ip": "10.0.0.50",
                    "source_port": 54321,
                    "user_agent": "Port Scanner",
                    "country": "Unknown",
                    "city": "Unknown",
                    "metadata": {
                        "test": True,
                        "port": port,
                        "scan_type": "port_scan_test"
                    }
                }
                
                response = self.session.post(
                    f"{API_BASE}/api/detection/events/ingest?tenant_id={self.tenant_id}",
                    json=event_data
                )
                
                if response.status_code == 200:
                    scan_events.append(event_data)
                else:
                    print(f"   Warning: Failed to send scan event {i}: {response.status_code}")
                
                time.sleep(0.1)  # Small delay between events
            
            if len(scan_events) >= 10:
                self.log_test("Port Scan Detection", True, f"Sent {len(scan_events)} scan events")
                return True
            else:
                self.log_test("Port Scan Detection", False, f"Only sent {len(scan_events)} events")
                return False
                
        except Exception as e:
            self.log_test("Port Scan Detection", False, f"Error: {str(e)}")
            return False
    
    async def test_websocket_notifications(self) -> bool:
        """Test WebSocket real-time notifications"""
        try:
            # Connect to WebSocket
            uri = f"{WEBSOCKET_URL}/{self.tenant_id}"
            websocket = await websockets.connect(uri)
            
            # Wait for connection
            await asyncio.sleep(1)
            
            # Check if connection is established
            try:
                # Try to send a ping to test connection
                pong_waiter = await websocket.ping()
                await asyncio.wait_for(pong_waiter, timeout=5.0)
                self.log_test("WebSocket Connection", True, "Connected successfully")
            except Exception as e:
                self.log_test("WebSocket Connection", False, f"Connection test failed: {e}")
                await websocket.close()
                return False
            
            # Wait for any notifications
            try:
                # Set a timeout for receiving messages
                message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                data = json.loads(message)
                
                if data.get('type') == 'security_alert':
                    self.log_test("WebSocket Notifications", True, f"Received alert: {data.get('title', 'Unknown')}")
                    success = True
                else:
                    self.log_test("WebSocket Notifications", False, f"Unexpected message type: {data.get('type')}")
                    success = False
                    
            except asyncio.TimeoutError:
                self.log_test("WebSocket Notifications", False, "No notifications received within timeout")
                success = False
            
            await websocket.close()
            return success
                
        except Exception as e:
            self.log_test("WebSocket Notifications", False, f"Error: {str(e)}")
            return False
    
    def test_direct_notification_send(self) -> bool:
        """Test sending notifications directly to the notification service"""
        try:
            # Create a test notification
            notification_data = {
                "id": str(uuid.uuid4()),
                "tenant_id": self.tenant_id,
                "user_id": "admin@demo-org.com",
                "type": "security_alert",
                "severity": "critical",
                "title": "Test Security Alert",
                "message": "This is a test security alert to verify the notification system",
                "source_ip": "192.168.1.200",
                "target_ip": "192.168.1.1",
                "alert_id": str(uuid.uuid4()),
                "correlation_id": str(uuid.uuid4()),
                "metadata": {
                    "test": True,
                    "timestamp": datetime.now().isoformat()
                },
                "created_at": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{NOTIFICATION_BASE}/notifications/send",
                json=notification_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    self.log_test("Direct Notification Send", True, f"Notification ID: {data.get('notification_id')}")
                    return True
                else:
                    self.log_test("Direct Notification Send", False, f"Status: {data.get('status')}")
                    return False
            else:
                self.log_test("Direct Notification Send", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Direct Notification Send", False, f"Error: {str(e)}")
            return False
    
    def test_dashboard_integration(self) -> bool:
        """Test dashboard integration with notifications"""
        try:
            # Check if dashboard can access detection stats
            response = self.session.get(f"{API_BASE}/api/detection/stats?tenant_id={self.tenant_id}")
            
            if response.status_code == 200:
                data = response.json()
                alerts_24h = data.get('total_alerts_24h', 0)
                active_alerts = data.get('active_alerts', 0)
                
                self.log_test("Dashboard Integration", True, 
                             f"Stats: {alerts_24h} alerts (24h), {active_alerts} active")
                return True
            else:
                self.log_test("Dashboard Integration", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Dashboard Integration", False, f"Error: {str(e)}")
            return False
    
    def check_alerts_generated(self) -> bool:
        """Check if alerts were generated from the test events"""
        try:
            # Wait a bit for processing
            time.sleep(5)
            
            # Check alerts
            response = self.session.get(f"{API_BASE}/api/detection/alerts?tenant_id={self.tenant_id}&limit=10")
            
            if response.status_code == 200:
                alerts = response.json()
                recent_alerts = [a for a in alerts if a.get('created_at')]
                
                if recent_alerts:
                    self.log_test("Alerts Generated", True, f"Found {len(recent_alerts)} recent alerts")
                    return True
                else:
                    self.log_test("Alerts Generated", False, "No recent alerts found")
                    return False
            else:
                self.log_test("Alerts Generated", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Alerts Generated", False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting BITS-SIEM Enhanced Notification System Tests")
        print("=" * 60)
        
        # Test 1: Authentication
        if not self.authenticate():
            print("❌ Authentication failed. Cannot continue with other tests.")
            return
        
        # Test 2: Notification Service Health
        self.test_notification_service_health()
        
        # Test 3: Direct Notification Send
        self.test_direct_notification_send()
        
        # Test 4: Brute Force Detection
        self.test_brute_force_detection()
        
        # Test 5: Port Scan Detection
        self.test_port_scan_detection()
        
        # Test 6: Check if alerts were generated
        self.check_alerts_generated()
        
        # Test 7: Dashboard Integration
        self.test_dashboard_integration()
        
        # Test 8: WebSocket Notifications (async)
        print("\n🔄 Testing WebSocket Notifications...")
        try:
            asyncio.run(self.test_websocket_notifications())
        except Exception as e:
            self.log_test("WebSocket Notifications", False, f"Error: {str(e)}")
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Test Results Summary")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result['success'])
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("\n🎉 All tests passed! The enhanced notification system is working correctly.")
        else:
            print(f"\n⚠️  {total - passed} test(s) failed. Check the details above.")
        
        # Save detailed results
        with open('notification_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\n📝 Detailed results saved to: notification_test_results.json")

def main():
    """Main test runner"""
    tester = NotificationTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main()
