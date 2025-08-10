#!/usr/bin/env python3
"""
Test script to simulate brute-force attacks and verify detection
"""

import socket
import time
import json
import random
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

def create_auth_failure_message(username, source_ip, tenant_id="acme", facility=10, severity=4):
    """Create a syslog authentication failure message"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    # Create a realistic SSH authentication failure log
    message_content = f"Failed password for {username} from {source_ip} port 22 ssh2"
    
    # RFC 5424 syslog format with JSON structured data
    syslog_message = f"<{facility * 8 + severity}>1 {timestamp} server01 sshd 12345 - " + \
                    f'[meta tenant_id="{tenant_id}" event_type="authentication_failure"] {message_content}'
    
    return syslog_message

def simulate_brute_force_attack():
    """Simulate a brute-force attack against multiple users"""
    print("🔥 Starting Brute-Force Attack Simulation")
    print("=" * 50)
    
    # Attack parameters
    syslog_host = "localhost"
    syslog_port = 514
    
    # Target users and attacking IPs
    target_users = ["admin", "user", "john.doe", "jane.smith", "administrator"]
    attacking_ips = ["192.168.1.100", "10.0.0.50", "172.16.1.200"]
    
    # Organizations to test
    organizations = [
        {"tenant_id": "acme", "name": "Acme Corp"},
        {"tenant_id": "beta", "name": "Beta Industries"},
        {"tenant_id": "cisco", "name": "Cisco Systems"}
    ]
    
    attack_scenarios = []
    
    # Scenario 1: Parallel attack (same IP attacking multiple users)
    print("\n📊 Scenario 1: Parallel Attack (Same IP → Multiple Users)")
    attacker_ip = attacking_ips[0]
    org = organizations[0]  # Acme Corp
    
    for i, username in enumerate(target_users):
        message = create_auth_failure_message(username, attacker_ip, org["tenant_id"])
        success = send_syslog_message(syslog_host, syslog_port, message)
        
        if success:
            print(f"  ✅ Sent auth failure: {username}@{org['name']} from {attacker_ip}")
            attack_scenarios.append({
                "type": "parallel",
                "org": org["name"],
                "tenant_id": org["tenant_id"],
                "user": username,
                "ip": attacker_ip
            })
        else:
            print(f"  ❌ Failed to send: {username}@{org['name']} from {attacker_ip}")
        
        time.sleep(0.5)  # Small delay between attempts
    
    time.sleep(2)  # Wait between scenarios
    
    # Scenario 2: Sequential attack (same user from multiple IPs)
    print("\n📊 Scenario 2: Sequential Attack (Multiple IPs → Same User)")
    target_user = "admin"
    org = organizations[1]  # Beta Industries
    
    for i, attacker_ip in enumerate(attacking_ips):
        message = create_auth_failure_message(target_user, attacker_ip, org["tenant_id"])
        success = send_syslog_message(syslog_host, syslog_port, message)
        
        if success:
            print(f"  ✅ Sent auth failure: {target_user}@{org['name']} from {attacker_ip}")
            attack_scenarios.append({
                "type": "sequential",
                "org": org["name"],
                "tenant_id": org["tenant_id"],
                "user": target_user,
                "ip": attacker_ip
            })
        else:
            print(f"  ❌ Failed to send: {target_user}@{org['name']} from {attacker_ip}")
        
        time.sleep(0.5)
    
    time.sleep(2)
    
    # Scenario 3: Distributed attack (multiple IPs, multiple users)
    print("\n📊 Scenario 3: Distributed Attack (Multiple IPs → Multiple Users)")
    org = organizations[2]  # Cisco Systems
    
    for i in range(8):  # Send 8 rapid attempts
        username = random.choice(target_users)
        attacker_ip = random.choice(attacking_ips)
        
        message = create_auth_failure_message(username, attacker_ip, org["tenant_id"])
        success = send_syslog_message(syslog_host, syslog_port, message)
        
        if success:
            print(f"  ✅ Sent auth failure: {username}@{org['name']} from {attacker_ip}")
            attack_scenarios.append({
                "type": "distributed",
                "org": org["name"],
                "tenant_id": org["tenant_id"],
                "user": username,
                "ip": attacker_ip
            })
        else:
            print(f"  ❌ Failed to send: {username}@{org['name']} from {attacker_ip}")
        
        time.sleep(0.3)  # Rapid attempts
    
    print("\n" + "=" * 50)
    print("🎯 Attack Simulation Complete!")
    print(f"📈 Total scenarios executed: {len(attack_scenarios)}")
    
    # Summary by organization
    org_summary = {}
    for scenario in attack_scenarios:
        org_name = scenario["org"]
        if org_name not in org_summary:
            org_summary[org_name] = {"count": 0, "tenant_id": scenario["tenant_id"], "types": set()}
        org_summary[org_name]["count"] += 1
        org_summary[org_name]["types"].add(scenario["type"])
    
    print("\n📋 Attack Summary by Organization:")
    for org_name, data in org_summary.items():
        attack_types = ", ".join(data["types"])
        print(f"  🏢 {org_name} (tenant: {data['tenant_id']})")
        print(f"     📊 {data['count']} attack attempts")
        print(f"     🎯 Attack types: {attack_types}")
    
    print("\n⏰ Waiting 10 seconds for processing...")
    time.sleep(10)
    
    return attack_scenarios, org_summary

def check_alerts_in_database():
    """Check if alerts were generated in the database"""
    print("\n🔍 Checking for Generated Alerts...")
    print("=" * 40)
    
    try:
        import requests
        
        # Check API for notifications (alerts)
        api_url = "http://localhost:8000"
        
        # Get notifications for each tenant
        tenants = ["acme", "beta", "cisco"]
        
        for tenant in tenants:
            try:
                response = requests.get(f"{api_url}/api/notifications", 
                                      headers={"X-Tenant-ID": tenant})
                
                if response.status_code == 200:
                    notifications = response.json()
                    
                    # Filter for security alerts
                    security_alerts = [n for n in notifications 
                                     if n.get('type') == 'security_alert']
                    
                    print(f"\n🏢 {tenant.upper()} Organization:")
                    print(f"   📧 Total notifications: {len(notifications)}")
                    print(f"   🚨 Security alerts: {len(security_alerts)}")
                    
                    if security_alerts:
                        for alert in security_alerts[-3:]:  # Show last 3 alerts
                            print(f"   ⚠️  {alert.get('title', 'Unknown Alert')}")
                            print(f"      📅 {alert.get('created_at', 'Unknown time')}")
                            if alert.get('event_metadata'):
                                metadata = alert['event_metadata']
                                if isinstance(metadata, dict):
                                    print(f"      🎯 Source IP: {metadata.get('source_ip', 'Unknown')}")
                                    print(f"      👤 Target User: {metadata.get('target_user', 'Unknown')}")
                else:
                    print(f"❌ Failed to get notifications for {tenant}: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error checking {tenant} alerts: {e}")
                
    except ImportError:
        print("❌ requests library not available, cannot check API")
    except Exception as e:
        print(f"❌ Error checking alerts: {e}")

if __name__ == "__main__":
    print("🛡️  BITS-SIEM Brute-Force Detection Test")
    print("=" * 50)
    print("This script will simulate brute-force attacks against different")
    print("organizations and verify that alerts are generated correctly.")
    print()
    
    # Run the attack simulation
    scenarios, summary = simulate_brute_force_attack()
    
    # Check for generated alerts
    check_alerts_in_database()
    
    print("\n✅ Test Complete!")
    print("\n📝 Next Steps:")
    print("1. Check the dashboard at http://localhost:3000")
    print("2. Login with organization credentials:")
    print("   - Acme: admin@acme.com / admin123")
    print("   - Beta: admin@beta.com / admin123") 
    print("   - Cisco: aspundir@cisco.com / admin123")
    print("3. Look for security alerts in notifications")
    print("4. Check processing service logs: docker logs bits-siem-processing-1")
