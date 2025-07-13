#!/usr/bin/env python3
"""
Test script for BITS-SIEM syslog ingestion and processing
"""

import socket
import time
import json
import requests
from datetime import datetime

def send_syslog_message(message, host='localhost', port=514):
    """Send a syslog message via UDP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode('utf-8'), (host, port))
        sock.close()
        print(f"✅ Sent: {message}")
        return True
    except Exception as e:
        print(f"❌ Failed to send: {e}")
        return False

def test_health_endpoints():
    """Test health endpoints of all services"""
    endpoints = [
        ("API", "http://localhost:8000/health"),
        ("Ingestion", "http://localhost:8001/health"),
        ("Processing", "http://localhost:8002/health")
    ]
    
    print("\n🔍 Testing Health Endpoints:")
    for service, url in endpoints:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {service}: {data.get('status', 'unknown')}")
            else:
                print(f"❌ {service}: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ {service}: {e}")

def test_syslog_formats():
    """Test different syslog formats"""
    print("\n📝 Testing Syslog Formats:")
    
    # RFC 3164 format
    rfc3164_messages = [
        "<134>Jan 15 10:30:00 webserver01 sshd[12345]: Failed password for user admin from 192.168.1.50",
        "<116>Jan 15 10:31:00 webserver01 kernel: Firewall: DROP IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=10.0.0.100 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=14600 RES=0x00 SYN URGP=0",
        "<165>Jan 15 10:32:00 database01 mysql: Access denied for user 'root'@'192.168.1.50' (using password: YES)"
    ]
    
    # RFC 5424 format
    rfc5424_messages = [
        "<34>1 2024-01-15T10:30:00.000Z webserver01.example.com sshd 12345 ID47 - Failed password for user admin",
        "<30>1 2024-01-15T10:31:00.000Z firewall01.example.com iptables 12346 ID48 - DROP IN=eth0 SRC=10.0.0.100 DST=192.168.1.100"
    ]
    
    # Cisco format
    cisco_messages = [
        "189 000001: %SYS-5-CONFIG_I: Configured from console by vty0 (10.0.0.1)",
        "190 000002: %SEC-6-IPACCESSLOGP: list 100 denied tcp 10.0.0.100(12345) -> 192.168.1.100(80), 1 packet",
        "191 000003: %AUTH-6-INFO: User 'admin' authentication failed from 192.168.1.50"
    ]
    
    # Test RFC 3164
    print("\n📋 RFC 3164 Format:")
    for msg in rfc3164_messages:
        send_syslog_message(msg)
        time.sleep(0.1)
    
    # Test RFC 5424
    print("\n📋 RFC 5424 Format:")
    for msg in rfc5424_messages:
        send_syslog_message(msg)
        time.sleep(0.1)
    
    # Test Cisco
    print("\n📋 Cisco Format:")
    for msg in cisco_messages:
        send_syslog_message(msg)
        time.sleep(0.1)

def test_threat_patterns():
    """Test threat pattern detection"""
    print("\n🚨 Testing Threat Patterns:")
    
    threat_messages = [
        # Brute force
        "<134>Jan 15 10:35:00 webserver01 sshd[12345]: Failed password for user admin from 192.168.1.50",
        "<134>Jan 15 10:35:01 webserver01 sshd[12345]: Failed password for user admin from 192.168.1.50",
        "<134>Jan 15 10:35:02 webserver01 sshd[12345]: Failed password for user admin from 192.168.1.50",
        
        # SQL injection
        "<134>Jan 15 10:36:00 webserver01 apache: GET /login.php?user=admin' OR '1'='1 HTTP/1.1",
        "<134>Jan 15 10:36:01 webserver01 apache: POST /search.php?q=union select * from users HTTP/1.1",
        
        # XSS
        "<134>Jan 15 10:37:00 webserver01 apache: GET /comment.php?msg=<script>alert('xss')</script> HTTP/1.1",
        
        # DoS
        "<134>Jan 15 10:38:00 firewall01 iptables: Connection rate limit exceeded from 10.0.0.100",
        
        # Malware
        "<134>Jan 15 10:39:00 antivirus01 clamav: virus detected in /tmp/malware.exe"
    ]
    
    for msg in threat_messages:
        send_syslog_message(msg)
        time.sleep(0.2)

def test_anomaly_detection():
    """Test anomaly detection with unusual patterns"""
    print("\n🔍 Testing Anomaly Detection:")
    
    # Normal messages
    normal_messages = [
        "<134>Jan 15 10:40:00 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        "<134>Jan 15 10:40:01 webserver01 apache: GET /index.html HTTP/1.1 200 1234",
        "<134>Jan 15 10:40:02 database01 mysql: Query: SELECT * FROM users WHERE id = 1"
    ]
    
    # Anomalous messages (unusual patterns)
    anomalous_messages = [
        "<134>Jan 15 10:41:00 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        "<134>Jan 15 10:41:01 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        "<134>Jan 15 10:41:02 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        "<134>Jan 15 10:41:03 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        "<134>Jan 15 10:41:04 webserver01 sshd[12345]: Accepted password for user admin from 192.168.1.50",
        # Unusual message with many special characters
        "<134>Jan 15 10:42:00 webserver01 app: !@#$%^&*()_+-=[]{}|;':\",./<>?`~ 1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ]
    
    print("📋 Normal Messages:")
    for msg in normal_messages:
        send_syslog_message(msg)
        time.sleep(0.1)
    
    print("📋 Anomalous Messages:")
    for msg in anomalous_messages:
        send_syslog_message(msg)
        time.sleep(0.1)

def check_processing_stats():
    """Check processing service statistics"""
    print("\n📊 Checking Processing Statistics:")
    try:
        response = requests.get("http://localhost:8002/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print("✅ Processing Service Stats:")
            print(f"   - Anomaly Detector Trained: {stats.get('anomaly_detector', {}).get('is_trained', False)}")
            print(f"   - Training Samples: {stats.get('anomaly_detector', {}).get('training_samples', 0)}")
            print(f"   - Threat Intelligence IPs: {stats.get('threat_intelligence', {}).get('malicious_ips', 0)}")
            print(f"   - Correlated Events: {stats.get('event_correlator', {}).get('correlated_events', 0)}")
        else:
            print(f"❌ Failed to get stats: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to get stats: {e}")

def check_ingestion_stats():
    """Check ingestion service statistics"""
    print("\n📊 Checking Ingestion Statistics:")
    try:
        response = requests.get("http://localhost:8001/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print("✅ Ingestion Service Stats:")
            print(f"   - Buffer Size: {stats.get('buffer_size', 0)}")
            print(f"   - Last Flush: {stats.get('last_flush', 0)}")
            print(f"   - Redis Connected: {stats.get('connections', {}).get('redis', False)}")
            print(f"   - Kafka Connected: {stats.get('connections', {}).get('kafka', False)}")
            print(f"   - Database Connected: {stats.get('connections', {}).get('database', False)}")
        else:
            print(f"❌ Failed to get stats: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to get stats: {e}")

def trigger_ml_training():
    """Trigger ML model training"""
    print("\n🤖 Triggering ML Model Training:")
    try:
        response = requests.post("http://localhost:8002/train", timeout=30)
        if response.status_code == 200:
            print("✅ ML training triggered successfully")
        else:
            print(f"❌ Failed to trigger training: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to trigger training: {e}")

def main():
    """Main test function"""
    print("🚀 BITS-SIEM Syslog Ingestion and Processing Test")
    print("=" * 60)
    
    # Test health endpoints
    test_health_endpoints()
    
    # Wait for services to be ready
    print("\n⏳ Waiting for services to be ready...")
    time.sleep(5)
    
    # Test different syslog formats
    test_syslog_formats()
    
    # Wait for processing
    print("\n⏳ Waiting for message processing...")
    time.sleep(10)
    
    # Check ingestion stats
    check_ingestion_stats()
    
    # Test threat patterns
    test_threat_patterns()
    
    # Wait for processing
    print("\n⏳ Waiting for threat processing...")
    time.sleep(10)
    
    # Test anomaly detection
    test_anomaly_detection()
    
    # Wait for processing
    print("\n⏳ Waiting for anomaly processing...")
    time.sleep(10)
    
    # Check processing stats
    check_processing_stats()
    
    # Trigger ML training
    trigger_ml_training()
    
    print("\n✅ Test completed!")
    print("\n📋 Next Steps:")
    print("1. Check the dashboard at http://localhost:3000")
    print("2. Monitor logs: docker-compose logs -f ingestion processing")
    print("3. Check database: docker-compose exec db psql -U siem -d siemdb")
    print("4. Monitor Kafka topics: docker-compose exec kafka kafka-topics --list --bootstrap-server localhost:9092")

if __name__ == "__main__":
    main() 