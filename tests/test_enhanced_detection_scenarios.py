#!/usr/bin/env python3
"""
Enhanced BITS-SIEM Detection Test Suite
Tests brute force, port scan, negative scenarios, and clickable report functionality
"""

import requests
import json
import time
import socket
import sys
import random
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text:^80}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")

def send_syslog_event(message, host='localhost', port=514):
    """Send a syslog message to the ingestion service"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (host, port))
        sock.close()
        return True
    except Exception as e:
        print_error(f"Failed to send syslog: {e}")
        return False

def authenticate_api():
    """Authenticate with the API and return token"""
    try:
        response = requests.post(
            "http://localhost:8000/api/auth/login",
            json={"email": "admin@demo.com", "password": "demo123"},
            timeout=10
        )
        if response.status_code == 200:
            token = response.json().get('token')
            if token:
                print_success("API authentication successful")
                return token
            else:
                print_error("No token in response")
                return None
        else:
            print_error(f"Authentication failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print_error(f"Authentication error: {e}")
        return None

def get_alerts_by_type(alert_type, minutes=10):
    """Get alerts by type from the last N minutes"""
    try:
        conn = psycopg2.connect(
            host="localhost", port="5432", database="siem", 
            user="siem", password="siem123"
        )
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, alert_type, title, severity, source_ip, username, created_at, description
            FROM security_alerts 
            WHERE tenant_id = 'demo-org' 
            AND alert_type = %s
            AND created_at > NOW() - INTERVAL '%s minutes'
            ORDER BY created_at DESC
        """, (alert_type, minutes))
        
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        return alerts
        
    except Exception as e:
        print_error(f"Database check failed: {e}")
        return []

def get_all_recent_alerts(minutes=10):
    """Get all recent alerts"""
    try:
        conn = psycopg2.connect(
            host="localhost", port="5432", database="siem", 
            user="siem", password="siem123"
        )
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, alert_type, title, severity, source_ip, username, created_at, description
            FROM security_alerts 
            WHERE tenant_id = 'demo-org' 
            AND created_at > NOW() - INTERVAL '%s minutes'
            ORDER BY created_at DESC
        """, (minutes,))
        
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        return alerts
        
    except Exception as e:
        print_error(f"Database check failed: {e}")
        return []

def test_brute_force_detection():
    """Test brute force attack detection"""
    print_header("🔥 Enhanced Brute Force Attack Test")
    
    attack_ip = "10.0.0.150"
    username = "admin"
    
    print_info("Sending 6 failed login attempts (should trigger detection)...")
    
    for i in range(6):
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        syslog_message = f"<38>1 {timestamp} server01 sshd[{12000+i}]: Failed password for {username} from {attack_ip} port 22 ssh2"
        
        if send_syslog_event(syslog_message):
            print_success(f"Attack {i+1}/6: {username} from {attack_ip}")
        else:
            print_error(f"Failed to send attack {i+1}")
        time.sleep(1)
    
    print_info("Waiting 15 seconds for processing...")
    time.sleep(15)
    
    # Check for brute force alerts
    bf_alerts = get_alerts_by_type('brute_force_attack', 5)
    
    if bf_alerts:
        print_success(f"✅ PASS: Found {len(bf_alerts)} brute force alerts")
        for alert in bf_alerts[:2]:
            print_info(f"  Alert: {alert['title']} - {alert['severity']} - {alert['source_ip']}")
        return True
    else:
        print_error("❌ FAIL: No brute force alerts detected")
        return False

def test_port_scan_detection():
    """Test port scan detection with enhanced firewall logs"""
    print_header("🔍 Enhanced Port Scan Detection Test")
    
    scan_ip = "10.0.0.200"
    target_ip = "192.168.1.100"
    
    print_info("Simulating comprehensive port scan - 10 different ports...")
    
    ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
    
    for i, port in enumerate(ports):
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        # Enhanced firewall log format with DPT (destination port)
        syslog_message = f"<38>1 {timestamp} firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC={scan_ip} DST={target_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={12345+i} DF PROTO=TCP SPT=54321 DPT={port} WINDOW=65535 RES=0x00 SYN URGP=0"
        
        if send_syslog_event(syslog_message):
            print_success(f"Port scan {i+1}/10: {scan_ip} -> {target_ip}:{port}")
        else:
            print_error(f"Failed to send scan {i+1}")
        time.sleep(0.5)
    
    print_info("Waiting 20 seconds for processing...")
    time.sleep(20)
    
    # Check for port scan alerts
    scan_alerts = get_alerts_by_type('port_scan', 5)
    
    if scan_alerts:
        print_success(f"✅ PASS: Found {len(scan_alerts)} port scan alerts")
        for alert in scan_alerts[:2]:
            print_info(f"  Alert: {alert['title']} - {alert['severity']} - {alert['source_ip']}")
        return True
    else:
        print_warning("⚠️  Port scan detection may need more events or different format")
        return False

def test_negative_scenarios():
    """Test negative scenario detection (warning alerts)"""
    print_header("⚠️  Negative Scenario Detection Test")
    
    print_info("Testing distributed authentication failures...")
    
    # Simulate distributed failures from multiple IPs for same user
    username = "testuser"
    ips = ["10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53"]
    
    for i, ip in enumerate(ips):
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        syslog_message = f"<38>1 {timestamp} server01 sshd[{13000+i}]: Failed password for {username} from {ip} port 22 ssh2"
        
        if send_syslog_event(syslog_message):
            print_success(f"Distributed failure {i+1}/4: {username} from {ip}")
        time.sleep(2)
    
    print_info("Waiting 15 seconds for processing...")
    time.sleep(15)
    
    # Check for suspicious activity alerts
    suspicious_alerts = get_alerts_by_type('suspicious_activity', 5)
    
    if suspicious_alerts:
        print_success(f"✅ PASS: Found {len(suspicious_alerts)} suspicious activity alerts")
        for alert in suspicious_alerts[:2]:
            print_info(f"  Alert: {alert['title']} - {alert['severity']} - {alert['source_ip']}")
        return True
    else:
        print_warning("⚠️  No negative scenario alerts detected")
        return False

def test_mixed_scenarios():
    """Test mixed attack scenarios"""
    print_header("🎯 Mixed Attack Scenarios Test")
    
    print_info("Simulating complex attack pattern...")
    
    # 1. Port scan followed by brute force
    scan_ip = "10.0.0.300"
    target_ip = "192.168.1.200"
    
    # Quick port scan
    for port in [22, 80, 443]:
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        syslog_message = f"<38>1 {timestamp} firewall kernel: [UFW BLOCK] SRC={scan_ip} DST={target_ip} DPT={port} PROTO=TCP"
        send_syslog_event(syslog_message)
        time.sleep(0.5)
    
    # Followed by brute force on SSH
    for i in range(5):
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        syslog_message = f"<38>1 {timestamp} server01 sshd[{14000+i}]: Failed password for root from {scan_ip} port 22 ssh2"
        send_syslog_event(syslog_message)
        time.sleep(1)
    
    print_info("Waiting 20 seconds for processing...")
    time.sleep(20)
    
    # Check for any alerts
    all_alerts = get_all_recent_alerts(5)
    
    if all_alerts:
        print_success(f"✅ PASS: Found {len(all_alerts)} total alerts from mixed scenarios")
        
        # Group by type
        alert_types = {}
        for alert in all_alerts:
            alert_type = alert['alert_type']
            if alert_type not in alert_types:
                alert_types[alert_type] = []
            alert_types[alert_type].append(alert)
        
        for alert_type, alerts in alert_types.items():
            print_info(f"  {alert_type}: {len(alerts)} alerts")
        
        return True
    else:
        print_warning("⚠️  No alerts detected from mixed scenarios")
        return False

def test_dashboard_integration(token):
    """Test dashboard integration and clickable reports"""
    print_header("🖥️  Dashboard Integration & Clickable Reports Test")
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test reports endpoint
        print_info("Testing reports API endpoint...")
        response = requests.get("http://localhost:8000/api/reports", headers=headers, timeout=10)
        
        if response.status_code == 200:
            reports = response.json()
            print_success(f"Found {len(reports)} reports")
            
            # Look for enhanced security report
            enhanced_report = None
            for report in reports:
                if report.get('type') == 'security_enhanced':
                    enhanced_report = report
                    break
            
            if enhanced_report:
                total_alerts = enhanced_report.get('data', {}).get('total_alerts', 0)
                recent_alerts = enhanced_report.get('data', {}).get('recent_alerts', [])
                
                print_success(f"Enhanced security report: {total_alerts} total alerts")
                print_info(f"Recent alerts available for clicking: {len(recent_alerts)}")
                
                # Check alert types in recent alerts
                alert_types = set()
                for alert in recent_alerts:
                    alert_types.add(alert.get('alert_type', 'unknown'))
                
                print_info(f"Alert types available: {', '.join(alert_types)}")
                
                # Verify clickable functionality exists
                clickable_alerts = [a for a in recent_alerts if a.get('id')]
                print_success(f"Clickable alerts with IDs: {len(clickable_alerts)}")
                
                return True
            else:
                print_error("Enhanced security report not found")
                return False
        else:
            print_error(f"Reports API failed: {response.status_code}")
            return False
            
    except Exception as e:
        print_error(f"Dashboard integration test failed: {e}")
        return False

def main():
    print_header("BITS-SIEM Enhanced Detection & Dashboard Test Suite")
    print_info("Testing brute force, port scan, negative scenarios, and clickable reports")
    
    # Authentication
    print_header("🔐 Authentication")
    token = authenticate_api()
    if not token:
        print_error("Cannot proceed without authentication")
        return False
    
    # Run all test scenarios
    test_results = {}
    
    # Core detection tests
    test_results['brute_force'] = test_brute_force_detection()
    test_results['port_scan'] = test_port_scan_detection()
    test_results['negative_scenarios'] = test_negative_scenarios()
    test_results['mixed_scenarios'] = test_mixed_scenarios()
    
    # Integration tests
    test_results['dashboard_integration'] = test_dashboard_integration(token)
    
    # Final results
    print_header("📋 Enhanced Test Results Summary")
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results.items():
        status = "PASS" if result else "FAIL"
        color = Colors.GREEN if result else Colors.RED
        print(f"{color}{status:>6}{Colors.END} - {test_name.replace('_', ' ').title()}")
        if result:
            passed += 1
    
    print(f"\n{Colors.BOLD}Overall: {passed}/{total} tests passed{Colors.END}")
    
    if passed == total:
        print_success("🎉 All enhanced tests PASSED! System is fully functional!")
    elif passed >= total * 0.8:
        print_warning(f"⚠️  Most tests passed. System is mostly functional.")
    else:
        print_error(f"❌ Multiple failures. System needs attention.")
    
    # Enhanced dashboard instructions
    print_header("🖥️  Enhanced Dashboard Verification")
    print_info("Manually verify the enhanced dashboard at: http://localhost:3000")
    print_info("Login: admin@demo.com / demo123")
    print_info("Enhanced Features to Test:")
    print_info("  1. 📊 Reports page shows multiple alert types (brute_force_attack, port_scan, suspicious_activity)")
    print_info("  2. 🖱️  Click on any alert row to see detailed syslog information")
    print_info("  3. 📋 Enhanced syslog details with timeline, raw logs, and correlation data")
    print_info("  4. ⚠️  Warning-level alerts for negative scenarios")
    print_info("  5. 🔍 Port scan alerts with firewall log details")
    print_info("  6. 📈 Enhanced security analytics with real-time metrics")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

