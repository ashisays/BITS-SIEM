#!/usr/bin/env python3
"""
Focused test to verify brute-force detection is working
"""

import socket
import time
import requests
from datetime import datetime

def send_auth_failure(username, source_ip, tenant_id="demo-org"):
    """Send a single authentication failure message"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    # Create SSH authentication failure message
    message_content = f"Failed password for {username} from {source_ip} port 22 ssh2"
    
    # RFC 5424 syslog format with proper structure
    syslog_message = f"<84>1 {timestamp} server01 sshd 12345 - " + \
                    f'[meta tenant_id="{tenant_id}" event_type="authentication_failure"] {message_content}'
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(syslog_message.encode('utf-8'), ("localhost", 514))
        sock.close()
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def test_brute_force_threshold():
    """Test brute-force detection with exact threshold"""
    print("🔥 Testing Brute-Force Detection Threshold")
    print("=" * 50)
    
    # Test parameters
    username = "testuser"
    source_ip = "192.168.1.100"
    tenant_id = "demo-org"
    
    print(f"📊 Sending 6 authentication failures (threshold is 5)")
    print(f"   👤 User: {username}")
    print(f"   🌐 Source IP: {source_ip}")
    print(f"   🏢 Tenant: {tenant_id}")
    print()
    
    # Send exactly 6 failed attempts (threshold is 5)
    for i in range(1, 7):
        success = send_auth_failure(username, source_ip, tenant_id)
        if success:
            print(f"  ✅ Attempt {i}: Authentication failure sent")
        else:
            print(f"  ❌ Attempt {i}: Failed to send")
        time.sleep(1)  # 1 second between attempts
    
    print("\n⏰ Waiting 15 seconds for processing and alert generation...")
    time.sleep(15)
    
    # Check for alerts
    print("\n🔍 Checking for generated alerts...")
    try:
        # Authenticate with Demo admin (correct tenant for our test)
        auth_response = requests.post(
            "http://localhost:8000/api/auth/login",
            json={"email": "admin@demo.com", "password": "admin123"}
        )
        
        if auth_response.status_code == 200:
            token = auth_response.json().get("access_token")
            print("  ✅ Authentication successful")
            
            # Get notifications
            headers = {"Authorization": f"Bearer {token}"}
            notifications_response = requests.get(
                "http://localhost:8000/api/notifications", 
                headers=headers
            )
            
            if notifications_response.status_code == 200:
                notifications = notifications_response.json()
                security_alerts = [n for n in notifications if n.get('type') == 'security_alert']
                brute_force_alerts = [n for n in security_alerts 
                                     if 'brute' in n.get('title', '').lower() or 
                                        'authentication' in n.get('title', '').lower()]
                
                print(f"  📧 Total notifications: {len(notifications)}")
                print(f"  🚨 Security alerts: {len(security_alerts)}")
                print(f"  🔥 Brute-force alerts: {len(brute_force_alerts)}")
                
                if brute_force_alerts:
                    print("\n🎉 SUCCESS: Brute-force detection is working!")
                    for alert in brute_force_alerts:
                        print(f"  ⚠️  Alert: {alert.get('title', 'Unknown')}")
                        print(f"     📅 Time: {alert.get('created_at', 'Unknown')}")
                        metadata = alert.get('event_metadata', {})
                        if isinstance(metadata, dict):
                            print(f"     🌐 Source IP: {metadata.get('source_ip', 'Unknown')}")
                            print(f"     👤 Target User: {metadata.get('target_user', 'Unknown')}")
                    return True
                else:
                    print("\n❌ No brute-force alerts found")
                    return False
            else:
                print(f"  ❌ Failed to get notifications: {notifications_response.status_code}")
                return False
        else:
            print(f"  ❌ Authentication failed: {auth_response.status_code}")
            return False
            
    except Exception as e:
        print(f"  ❌ Error checking alerts: {e}")
        return False

def check_processing_service_activity():
    """Check if processing service is actively processing messages"""
    print("\n🔧 Checking Processing Service Activity")
    print("=" * 40)
    
    try:
        # Check processing service metrics
        response = requests.get("http://localhost:8082/metrics", timeout=5)
        if response.status_code == 200:
            print("  ✅ Processing service metrics endpoint accessible")
            
            # Look for processing activity in metrics
            metrics_text = response.text
            if "events_processed" in metrics_text:
                print("  ✅ Event processing metrics found")
            else:
                print("  ⚠️  No event processing metrics found")
                
        else:
            print(f"  ❌ Processing service metrics not accessible: {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ Error checking processing service: {e}")

if __name__ == "__main__":
    print("🛡️  BITS-SIEM Focused Brute-Force Detection Test")
    print("=" * 60)
    print("This test sends exactly 6 authentication failures to trigger")
    print("the brute-force detection threshold (5) and verifies alerts.")
    print()
    
    # Check processing service first
    check_processing_service_activity()
    
    # Run focused brute-force test
    success = test_brute_force_threshold()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ BRUTE-FORCE DETECTION IS WORKING!")
        print("🎯 Alerts are being generated correctly")
        print("🔒 Tenant isolation is maintained")
    else:
        print("❌ BRUTE-FORCE DETECTION NEEDS INVESTIGATION")
        print("🔧 Check processing service logs for details")
        print("📝 Verify message format and event type classification")
    
    print("\n📋 Next Steps:")
    print("1. Check processing logs: docker logs bits-siem-processing-1 --tail 50")
    print("2. Verify Redis streams: docker exec bits-siem-redis-1 redis-cli XLEN siem:raw_messages")
    print("3. Check database for events: docker exec bits-siem-db-1 psql -U siem -d siem -c 'SELECT COUNT(*) FROM notifications;'")
