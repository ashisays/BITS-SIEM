#!/usr/bin/env python3
"""
Simple Brute Force Detection Test
================================

This test focuses specifically on testing the brute force detection functionality
by sending a series of authentication failure events and verifying that alerts are generated.
"""

import socket
import time
import json
import requests
import sys
import os
from datetime import datetime

def send_syslog_message(host, port, message):
    """Send a syslog message to the ingestion service"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode('utf-8'), (host, port))
        sock.close()
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def create_auth_failure_message(username, source_ip, tenant_id="demo-org"):
    """Create a syslog authentication failure message"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    message_content = f"Failed password for {username} from {source_ip} port 22 ssh2"
    
    syslog_message = f"<74>1 {timestamp} demo-server01 sshd 12345 - " + \
                    f'[meta tenant_id="{tenant_id}" event_type="authentication_failure"] {message_content}'
    
    return syslog_message

def test_brute_force_detection():
    """Test brute force detection by sending multiple failed login attempts"""
    print("🔥 Testing Brute Force Detection")
    print("=" * 50)
    
    # Configuration
    syslog_host = "localhost"
    syslog_port = 514
    api_base = "http://localhost:8000"
    
    # Test credentials
    email = "admin@demo.com"
    password = "demo123"
    
    # Get authentication token
    print("🔐 Authenticating with API...")
    try:
        login_data = {"email": email, "password": password}
        response = requests.post(f"{api_base}/api/auth/login", json=login_data, timeout=10)
        
        if response.status_code != 200:
            print(f"❌ Authentication failed: {response.status_code}")
            return False
        
        auth_data = response.json()
        token = auth_data.get("token")
        csrf_token = auth_data.get("csrf_token")
        
        if not token:
            print("❌ No token received")
            return False
        
        print("✅ Authentication successful")
        
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return False
    
    # Send brute force attack
    print("\n🔥 Sending Brute Force Attack...")
    attacker_ip = "10.0.0.100"
    target_user = "admin"
    
    # Send 10 failed login attempts rapidly
    for i in range(10):
        message = create_auth_failure_message(target_user, attacker_ip)
        success = send_syslog_message(syslog_host, syslog_port, message)
        
        if success:
            print(f"  ✅ Attack {i+1}/10: {target_user} from {attacker_ip}")
        else:
            print(f"  ❌ Attack {i+1}/10: Failed to send")
        
        time.sleep(0.1)  # Very rapid attacks
    
    print("\n⏰ Waiting 15 seconds for processing...")
    time.sleep(15)
    
    # Check for alerts
    print("\n🔍 Checking for Generated Alerts...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    
    try:
        # Check notifications
        response = requests.get(f"{api_base}/api/notifications", headers=headers, timeout=10)
        
        if response.status_code == 200:
            notifications = response.json()
            print(f"📊 Total notifications: {len(notifications)}")
            
            # Look for brute force related alerts
            bruteforce_alerts = [
                n for n in notifications 
                if any(keyword in n.get('title', '').lower() or keyword in n.get('description', '').lower()
                      for keyword in ['brute', 'force', 'attack', 'authentication', 'login', 'failure'])
            ]
            
            print(f"🚨 Brute force alerts: {len(bruteforce_alerts)}")
            
            if bruteforce_alerts:
                print("\n📋 Brute Force Alerts Found:")
                for i, alert in enumerate(bruteforce_alerts[:3]):  # Show first 3
                    print(f"  {i+1}. {alert.get('title', 'No title')}")
                    print(f"     Description: {alert.get('description', 'No description')[:100]}...")
                    print(f"     Severity: {alert.get('severity', 'Unknown')}")
                    print(f"     Created: {alert.get('created_at', 'Unknown')}")
                    print()
                
                return True
            else:
                print("⚠️ No brute force alerts found")
                
                # Show all notifications for debugging
                print("\n📋 All Notifications:")
                for i, notification in enumerate(notifications[:5]):
                    print(f"  {i+1}. {notification.get('title', 'No title')}")
                    print(f"     Type: {notification.get('type', 'Unknown')}")
                    print(f"     Description: {notification.get('description', 'No description')[:50]}...")
                    print()
                
                return False
        else:
            print(f"❌ Failed to get notifications: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking alerts: {e}")
        return False

def main():
    """Main entry point"""
    print("BITS-SIEM Simple Brute Force Detection Test")
    print("=" * 60)
    
    success = test_brute_force_detection()
    
    if success:
        print("\n🎉 Brute force detection test PASSED!")
        print("✅ Alerts were generated for the brute force attack")
    else:
        print("\n⚠️ Brute force detection test FAILED!")
        print("❌ No alerts were generated for the brute force attack")
    
    print("\n📝 Next Steps:")
    print("1. Check the dashboard at http://localhost:3000")
    print("2. Login with: admin@demo.com / demo123")
    print("3. Go to Notifications page to see alerts")
    print("4. Check processing service logs: docker logs bits-siem-processing")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
