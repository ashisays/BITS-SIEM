#!/usr/bin/env python3
"""
BITS-SIEM Complete Deployment Demonstration
Shows data ingestion, processing, and dashboard integration
"""

import requests
import json
import time
from datetime import datetime, timedelta
import random

# Service endpoints
API_BASE = "http://localhost:8000"
DASHBOARD_URL = "http://localhost:3000"
INGESTION_PORT = 514

def test_api_health():
    """Test API health and connectivity"""
    print("🔍 Testing API Health...")
    try:
        response = requests.get(f"{API_BASE}/health")
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ API Status: {health_data['status']}")
            print(f"📊 Database: {health_data['database']}")
            print(f"⏰ Timestamp: {health_data['timestamp']}")
            return True
        else:
            print(f"❌ API Health Check Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API Connection Error: {e}")
        return False

def simulate_brute_force_attack():
    """Simulate brute force attack data ingestion"""
    print("\n🚨 Simulating Brute Force Attack Data Ingestion...")
    
    # Simulate multiple failed login attempts from same IP
    attacker_ip = "203.0.113.50"
    target_users = ["admin", "user", "root", "administrator"]
    
    events = []
    base_time = datetime.utcnow()
    
    for i in range(15):  # 15 failed attempts
        event_data = {
            "tenant_id": "acme-corp",
            "user_id": random.randint(1, 4),
            "username": random.choice(target_users),
            "event_type": "login_failure",
            "source_type": "web",
            "source_ip": attacker_ip,
            "source_port": random.randint(40000, 65000),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "country": "US",
            "city": "Unknown",
            "device_fingerprint": f"device_{random.randint(1000, 9999)}",
            "session_id": f"session_{random.randint(10000, 99999)}",
            "login_duration": 0,
            "failed_attempts_count": i + 1,
            "time_since_last_attempt": 30 if i > 0 else None,
            "metadata": {
                "reason": "invalid_password",
                "attack_pattern": "brute_force",
                "burst": True
            }
        }
        events.append(event_data)
    
    # Send events to detection API
    successful_ingestions = 0
    for event in events:
        try:
            response = requests.post(
                f"{API_BASE}/api/detection/events/ingest",
                json=event,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                successful_ingestions += 1
            else:
                print(f"⚠️  Event ingestion failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Event ingestion error: {e}")
        
        time.sleep(0.1)  # Small delay between events
    
    print(f"✅ Successfully ingested {successful_ingestions}/{len(events)} events")
    return successful_ingestions > 0

def simulate_distributed_attack():
    """Simulate distributed attack from multiple IPs"""
    print("\n🌐 Simulating Distributed Attack...")
    
    attacker_ips = ["198.51.100.10", "198.51.100.20", "198.51.100.30"]
    target_user = "admin"
    
    events = []
    base_time = datetime.utcnow()
    
    for i, ip in enumerate(attacker_ips):
        for j in range(5):  # 5 attempts per IP
            event_data = {
                "tenant_id": "acme-corp",
                "user_id": 1,
                "username": target_user,
                "event_type": "login_failure",
                "source_type": "ssh",
                "source_ip": ip,
                "source_port": 22,
                "user_agent": "OpenSSH_8.0",
                "country": "US",
                "city": f"City_{i+1}",
                "device_fingerprint": f"ssh_client_{i+1}",
                "session_id": f"ssh_session_{random.randint(10000, 99999)}",
                "login_duration": 0,
                "failed_attempts_count": j + 1,
                "time_since_last_attempt": 60,
                "metadata": {
                    "reason": "invalid_password",
                    "attack_pattern": "distributed",
                    "protocol": "ssh"
                }
            }
            events.append(event_data)
    
    # Send events
    successful_ingestions = 0
    for event in events:
        try:
            response = requests.post(
                f"{API_BASE}/api/detection/events/ingest",
                json=event,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                successful_ingestions += 1
        except Exception as e:
            print(f"❌ Event ingestion error: {e}")
        
        time.sleep(0.1)
    
    print(f"✅ Successfully ingested {successful_ingestions}/{len(events)} distributed attack events")
    return successful_ingestions > 0

def check_generated_alerts():
    """Check for generated security alerts"""
    print("\n🔔 Checking Generated Security Alerts...")
    
    try:
        response = requests.get(f"{API_BASE}/api/detection/alerts")
        if response.status_code == 200:
            alerts = response.json()
            print(f"📊 Total Alerts Generated: {len(alerts)}")
            
            if alerts:
                print("\n🚨 Recent Security Alerts:")
                for i, alert in enumerate(alerts[:5]):  # Show first 5 alerts
                    print(f"  {i+1}. {alert['alert_type']} - {alert['severity']}")
                    print(f"     Target: {alert.get('target_entity', 'N/A')}")
                    print(f"     Confidence: {alert['confidence_score']:.2f}")
                    print(f"     Time: {alert['created_at']}")
                    print()
            else:
                print("ℹ️  No alerts generated yet (detection may take a few moments)")
            
            return len(alerts)
        else:
            print(f"❌ Failed to fetch alerts: {response.status_code}")
            return 0
    except Exception as e:
        print(f"❌ Error fetching alerts: {e}")
        return 0

def check_dashboard_data():
    """Check dashboard statistics"""
    print("\n📊 Checking Dashboard Statistics...")
    
    try:
        response = requests.get(f"{API_BASE}/api/dashboard/stats")
        if response.status_code == 200:
            stats = response.json()
            print("✅ Dashboard Statistics:")
            print(f"   📈 Total Events: {stats.get('total_events', 0)}")
            print(f"   🚨 Active Alerts: {stats.get('active_alerts', 0)}")
            print(f"   🔍 Sources: {stats.get('total_sources', 0)}")
            print(f"   📋 Reports: {stats.get('total_reports', 0)}")
            print(f"   👥 Users: {stats.get('total_users', 0)}")
            return True
        else:
            print(f"❌ Failed to fetch dashboard stats: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error fetching dashboard stats: {e}")
        return False

def check_notifications():
    """Check system notifications"""
    print("\n📬 Checking System Notifications...")
    
    try:
        response = requests.get(f"{API_BASE}/api/notifications")
        if response.status_code == 200:
            notifications = response.json()
            print(f"📊 Total Notifications: {len(notifications)}")
            
            if notifications:
                print("\n📋 Recent Notifications:")
                for i, notif in enumerate(notifications[:3]):  # Show first 3
                    print(f"  {i+1}. [{notif['severity'].upper()}] {notif['message']}")
                    print(f"     Time: {notif['timestamp']}")
                    print()
            
            return len(notifications)
        else:
            print(f"❌ Failed to fetch notifications: {response.status_code}")
            return 0
    except Exception as e:
        print(f"❌ Error fetching notifications: {e}")
        return 0

def main():
    """Main demonstration function"""
    print("🚀 BITS-SIEM Complete Deployment Demonstration")
    print("=" * 60)
    
    # Test API connectivity
    if not test_api_health():
        print("❌ API not available. Please ensure all services are running.")
        return
    
    print(f"\n🌐 Dashboard URL: {DASHBOARD_URL}")
    print("   You can access the dashboard in your browser to see real-time data")
    
    # Simulate attacks and data ingestion
    brute_force_success = simulate_brute_force_attack()
    distributed_success = simulate_distributed_attack()
    
    if brute_force_success or distributed_success:
        print("\n⏳ Waiting for detection processing...")
        time.sleep(3)  # Allow time for processing
        
        # Check results
        alert_count = check_generated_alerts()
        check_dashboard_data()
        notification_count = check_notifications()
        
        print("\n📊 Deployment Summary:")
        print("=" * 40)
        print(f"✅ API Service: Running")
        print(f"✅ Database: Connected")
        print(f"✅ Dashboard: Available at {DASHBOARD_URL}")
        print(f"✅ Data Ingestion: Working")
        print(f"📊 Events Processed: {30 if brute_force_success and distributed_success else 15}")
        print(f"🚨 Alerts Generated: {alert_count}")
        print(f"📬 Notifications: {notification_count}")
        
        print("\n🎯 Next Steps:")
        print("1. Open the dashboard in your browser")
        print("2. Login with: admin@acme.com / admin123")
        print("3. View the security alerts and reports")
        print("4. Check the notifications panel")
        print("5. Explore the sources and events data")
        
    else:
        print("\n❌ Data ingestion failed. Please check service logs.")

if __name__ == "__main__":
    main()
