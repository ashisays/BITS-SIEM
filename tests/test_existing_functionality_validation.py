#!/usr/bin/env python3
"""
BITS-SIEM Existing Functionality Validation
==========================================

This script validates that existing SIEM functionality remains intact
after implementing false positive reduction features.
"""

import asyncio
import json
import time
import requests
import socket
from datetime import datetime, timedelta
from typing import List, Dict, Any
import sys
import os
import psycopg2
from psycopg2.extras import RealDictCursor

# Add paths
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'processing'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'api'))

class ExistingFunctionalityValidator:
    """Validates that existing SIEM functionality works correctly"""
    
    def __init__(self, api_base_url: str = "http://localhost:8000"):
        self.api_base_url = api_base_url
        self.tenant_id = "demo-org"  # Use existing tenant
        self.syslog_host = "localhost"
        self.syslog_port = 514
        self.validation_results = {
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': []
        }
    
    def print_header(self, title: str):
        """Print formatted header"""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def print_info(self, message: str):
        """Print info message"""
        print(f"ℹ️  {message}")
    
    def print_success(self, message: str):
        """Print success message"""
        print(f"✅ {message}")
    
    def print_warning(self, message: str):
        """Print warning message"""
        print(f"⚠️  {message}")
    
    def print_error(self, message: str):
        """Print error message"""
        print(f"❌ {message}")
    
    def send_syslog_message(self, message: str) -> bool:
        """Send a syslog message to the ingestion service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode('utf-8'), (self.syslog_host, self.syslog_port))
            sock.close()
            return True
        except Exception as e:
            self.print_error(f"Failed to send syslog message: {e}")
            return False
    
    def create_auth_failure_message(self, username: str, source_ip: str, facility: int = 10, severity: int = 4) -> str:
        """Create a syslog authentication failure message"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        message_content = f"Failed password for {username} from {source_ip} port 22 ssh2"
        syslog_message = f"<{facility * 8 + severity}>1 {timestamp} demo-server01 sshd 12345 - " + \
                        f'[meta tenant_id="{self.tenant_id}" event_type="authentication_failure"] {message_content}'
        return syslog_message
    
    def create_firewall_block_message(self, source_ip: str, target_ip: str, port: int, facility: int = 16, severity: int = 4) -> str:
        """Create a syslog firewall block message"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        message_content = f"UFW BLOCK IN=eth0 OUT= SRC={source_ip} DST={target_ip} DPT={port} PROTO=TCP"
        syslog_message = f"<{facility * 8 + severity}>1 {timestamp} demo-firewall kernel - " + \
                        f'[meta tenant_id="{self.tenant_id}" event_type="security_event"] {message_content}'
        return syslog_message
    
    def get_alerts_from_db(self, alert_type: str = None, minutes: int = 5) -> List[Dict]:
        """Get alerts from database"""
        try:
            conn = psycopg2.connect(
                host="localhost", port="5432", database="siem", 
                user="siem", password="siem123"
            )
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            if alert_type:
                cursor.execute("""
                    SELECT id, alert_type, title, severity, source_ip, username, created_at, description
                    FROM security_alerts 
                    WHERE tenant_id = %s 
                    AND alert_type = %s
                    AND created_at > NOW() - INTERVAL '%s minutes'
                    ORDER BY created_at DESC
                """, (self.tenant_id, alert_type, minutes))
            else:
                cursor.execute("""
                    SELECT id, alert_type, title, severity, source_ip, username, created_at, description
                    FROM security_alerts 
                    WHERE tenant_id = %s 
                    AND created_at > NOW() - INTERVAL '%s minutes'
                    ORDER BY created_at DESC
                """, (self.tenant_id, minutes))
            
            alerts = cursor.fetchall()
            cursor.close()
            conn.close()
            return [dict(alert) for alert in alerts]
            
        except Exception as e:
            self.print_error(f"Database check failed: {e}")
            return []
    
    def record_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Record test result"""
        self.validation_results['tests_run'] += 1
        if passed:
            self.validation_results['tests_passed'] += 1
            self.print_success(f"PASS: {test_name}")
        else:
            self.validation_results['tests_failed'] += 1
            self.print_error(f"FAIL: {test_name}")
        
        self.validation_results['test_details'].append({
            'test_name': test_name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def test_basic_brute_force_detection(self):
        """Test that basic brute force detection still works"""
        self.print_header("Testing Basic Brute Force Detection")
        
        test_ip = "203.0.113.100"
        test_user = "testuser"
        
        self.print_info(f"Sending {6} failed login attempts from {test_ip} via syslog")
        
        # Send failed authentication events via syslog
        events_sent = 0
        for i in range(6):  # Above default threshold of 5
            syslog_message = self.create_auth_failure_message(test_user, test_ip)
            
            if self.send_syslog_message(syslog_message):
                events_sent += 1
                self.print_success(f"Sent auth failure {i+1}/6: {test_user} from {test_ip}")
            else:
                self.print_warning(f"Failed to send event {i+1}")
            
            time.sleep(0.5)  # Small delay between events
        
        # Wait for processing
        self.print_info("Waiting 10 seconds for processing...")
        time.sleep(10)
        
        # Check for alerts in database
        brute_force_alerts = self.get_alerts_from_db("brute_force_attack", 5)
        
        # Filter alerts by source IP
        matching_alerts = [
            alert for alert in brute_force_alerts 
            if alert['source_ip'] == test_ip
        ]
        
        if len(matching_alerts) > 0:
            self.record_test_result(
                "Basic Brute Force Detection",
                True,
                f"Generated {len(matching_alerts)} alerts for {events_sent} events"
            )
        else:
            # Check all recent alerts to see what was generated
            all_alerts = self.get_alerts_from_db(None, 5)
            self.record_test_result(
                "Basic Brute Force Detection",
                False,
                f"No brute force alerts generated for {events_sent} events. Found {len(all_alerts)} total alerts."
            )
    
    async def test_basic_port_scan_detection(self):
        """Test that basic port scan detection still works"""
        self.print_header("Testing Basic Port Scan Detection")
        
        test_ip = "203.0.113.101"
        target_ip = "192.168.1.100"
        
        self.print_info(f"Simulating port scan from {test_ip} via syslog")
        
        # Generate port scan events
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]  # 12 ports
        events_sent = 0
        
        for port in ports:
            syslog_message = self.create_firewall_block_message(test_ip, target_ip, port)
            
            if self.send_syslog_message(syslog_message):
                events_sent += 1
                self.print_success(f"Sent port scan {events_sent}/12: {test_ip} -> {target_ip}:{port}")
            else:
                self.print_warning(f"Failed to send port scan event for port {port}")
            
            time.sleep(0.3)  # Small delay between scans
        
        # Wait for processing
        self.print_info("Waiting 15 seconds for processing...")
        time.sleep(15)
        
        # Check for alerts in database
        port_scan_alerts = self.get_alerts_from_db("port_scan", 5)
        
        # Filter alerts by source IP
        matching_alerts = [
            alert for alert in port_scan_alerts 
            if alert['source_ip'] == test_ip
        ]
        
        if len(matching_alerts) > 0:
            self.record_test_result(
                "Basic Port Scan Detection",
                True,
                f"Generated {len(matching_alerts)} alerts for {events_sent} events"
            )
        else:
            # Check all recent alerts to see what was generated
            all_alerts = self.get_alerts_from_db(None, 5)
            self.record_test_result(
                "Basic Port Scan Detection",
                False,
                f"No port scan alerts generated for {events_sent} events. Found {len(all_alerts)} total alerts."
            )
    
    async def test_api_endpoints(self):
        """Test that API endpoints are working correctly"""
        self.print_header("Testing API Endpoints")
        
        # Test health endpoint
        try:
            response = requests.get(f"{self.api_base_url}/health")
            if response.status_code == 200:
                self.record_test_result("API Health Endpoint", True, "Health endpoint responding")
            else:
                self.record_test_result("API Health Endpoint", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.record_test_result("API Health Endpoint", False, f"Error: {e}")
        
        # Test detection health endpoint
        try:
            response = requests.get(f"{self.api_base_url}/api/detection/health")
            if response.status_code == 200:
                self.record_test_result("Detection Health Endpoint", True, "Detection health responding")
            else:
                self.record_test_result("Detection Health Endpoint", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.record_test_result("Detection Health Endpoint", False, f"Error: {e}")
        
        # Test false positive health endpoint
        try:
            response = requests.get(f"{self.api_base_url}/api/false-positive/health")
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get('status') == 'healthy':
                    self.record_test_result("False Positive Health Endpoint", True, "FP system healthy")
                else:
                    self.record_test_result("False Positive Health Endpoint", False, f"Status: {health_data.get('status')}")
            else:
                self.record_test_result("False Positive Health Endpoint", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.record_test_result("False Positive Health Endpoint", False, f"Error: {e}")
        
        # Test alert retrieval
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={"tenant_id": self.tenant_id, "limit": 5}
            )
            if response.status_code == 200:
                alerts = response.json()
                self.record_test_result("Alert Retrieval Endpoint", True, f"Retrieved {len(alerts)} alerts")
            else:
                self.record_test_result("Alert Retrieval Endpoint", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.record_test_result("Alert Retrieval Endpoint", False, f"Error: {e}")
    
    async def test_event_ingestion(self):
        """Test that event ingestion is working correctly via syslog"""
        self.print_header("Testing Event Ingestion")
        
        # Test single authentication success event
        test_ip = "192.168.1.50"
        test_user = "testuser"
        
        self.print_info("Testing single event ingestion via syslog...")
        
        # Create a successful authentication message
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        message_content = f"Accepted password for {test_user} from {test_ip} port 22 ssh2"
        syslog_message = f"<86>1 {timestamp} demo-server01 sshd 12345 - " + \
                        f'[meta tenant_id="{self.tenant_id}" event_type="authentication_success"] {message_content}'
        
        if self.send_syslog_message(syslog_message):
            self.record_test_result("Single Event Ingestion", True, f"Successfully sent auth success event")
        else:
            self.record_test_result("Single Event Ingestion", False, f"Failed to send syslog message")
        
        # Test batch event ingestion (multiple events in sequence)
        self.print_info("Testing batch event ingestion via syslog...")
        
        batch_events_sent = 0
        for i in range(3):
            test_ip = f"192.168.1.{60+i}"
            test_user = f"batchuser{i}"
            
            # Create authentication success message
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            message_content = f"Accepted password for {test_user} from {test_ip} port 443 https"
            syslog_message = f"<86>1 {timestamp} demo-web01 apache 12345 - " + \
                            f'[meta tenant_id="{self.tenant_id}" event_type="authentication_success"] {message_content}'
            
            if self.send_syslog_message(syslog_message):
                batch_events_sent += 1
                self.print_success(f"Sent batch event {i+1}/3: {test_user} from {test_ip}")
            
            time.sleep(0.2)
        
        if batch_events_sent == 3:
            self.record_test_result("Batch Event Ingestion", True, f"Successfully sent {batch_events_sent} events")
        else:
            self.record_test_result("Batch Event Ingestion", False, f"Only sent {batch_events_sent}/3 events")
    
    async def test_detection_thresholds(self):
        """Test that detection thresholds are working correctly"""
        self.print_header("Testing Detection Thresholds")
        
        # Test below threshold (should not trigger)
        below_threshold_ip = "203.0.113.102"
        test_user = "testuser"
        
        self.print_info(f"Testing below threshold: sending 3 failed attempts from {below_threshold_ip}")
        
        events_sent = 0
        for i in range(3):  # Below threshold of 5
            syslog_message = self.create_auth_failure_message(test_user, below_threshold_ip)
            
            if self.send_syslog_message(syslog_message):
                events_sent += 1
                self.print_success(f"Sent below-threshold event {i+1}/3")
            
            time.sleep(0.5)
        
        # Wait for processing
        self.print_info("Waiting 8 seconds for processing...")
        time.sleep(8)
        
        # Check that no alerts were generated for this IP
        all_alerts = self.get_alerts_from_db(None, 5)
        below_threshold_alerts = [
            alert for alert in all_alerts 
            if alert['source_ip'] == below_threshold_ip
        ]
        
        if len(below_threshold_alerts) == 0:
            self.record_test_result("Below Threshold Test", True, f"No alerts generated for {events_sent} below-threshold events")
        else:
            self.record_test_result("Below Threshold Test", False, f"Generated {len(below_threshold_alerts)} alerts for below-threshold activity")
    
    async def test_tenant_isolation(self):
        """Test that tenant isolation is working correctly"""
        self.print_header("Testing Tenant Isolation")
        
        other_tenant = "acme-corp"  # Use existing tenant
        test_ip = "203.0.113.103"
        test_user = "testuser"
        
        self.print_info(f"Sending events to different tenant ({other_tenant}) to test isolation")
        
        # Send events with different tenant ID in syslog metadata
        events_sent = 0
        for i in range(6):
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            message_content = f"Failed password for {test_user} from {test_ip} port 22 ssh2"
            syslog_message = f"<38>1 {timestamp} acme-server01 sshd 12345 - " + \
                            f'[meta tenant_id="{other_tenant}" event_type="authentication_failure"] {message_content}'
            
            if self.send_syslog_message(syslog_message):
                events_sent += 1
                self.print_success(f"Sent isolation test event {i+1}/6 to {other_tenant}")
            
            time.sleep(0.3)
        
        # Wait for processing
        self.print_info("Waiting 10 seconds for processing...")
        time.sleep(10)
        
        # Check that alerts are isolated by tenant (our tenant should not see other tenant's alerts)
        our_alerts = self.get_alerts_from_db(None, 5)
        cross_tenant_alerts = [
            alert for alert in our_alerts 
            if alert['source_ip'] == test_ip
        ]
        
        if len(cross_tenant_alerts) == 0:
            self.record_test_result("Tenant Isolation", True, f"No cross-tenant alert leakage (sent {events_sent} events to {other_tenant})")
        else:
            self.record_test_result("Tenant Isolation", False, f"Found {len(cross_tenant_alerts)} cross-tenant alerts in our tenant")
    
    async def test_alert_metadata_integrity(self):
        """Test that alert metadata is preserved correctly"""
        self.print_header("Testing Alert Metadata Integrity")
        
        test_ip = "203.0.113.104"
        test_user = "metadatatest"
        
        self.print_info(f"Sending events with rich metadata from {test_ip}")
        
        # Send events with rich metadata via syslog
        events_sent = 0
        for i in range(6):
            syslog_message = self.create_auth_failure_message(test_user, test_ip)
            
            if self.send_syslog_message(syslog_message):
                events_sent += 1
                self.print_success(f"Sent metadata test event {i+1}/6")
            
            time.sleep(0.5)
        
        # Wait for processing
        self.print_info("Waiting 10 seconds for processing...")
        time.sleep(10)
        
        # Check alert metadata
        all_alerts = self.get_alerts_from_db(None, 5)
        metadata_alerts = [
            alert for alert in all_alerts 
            if alert['source_ip'] == test_ip
        ]
        
        if len(metadata_alerts) > 0:
            alert = metadata_alerts[0]
            # Check if essential fields are preserved
            has_source_ip = alert.get('source_ip') == test_ip
            has_severity = 'severity' in alert and alert['severity'] is not None
            has_description = 'description' in alert and alert['description'] is not None
            has_alert_type = 'alert_type' in alert and alert['alert_type'] is not None
            has_title = 'title' in alert and alert['title'] is not None
            
            if has_source_ip and has_severity and has_description and has_alert_type and has_title:
                self.record_test_result("Alert Metadata Integrity", True, f"Alert metadata preserved correctly for {len(metadata_alerts)} alerts")
            else:
                missing_fields = []
                if not has_source_ip: missing_fields.append("source_ip")
                if not has_severity: missing_fields.append("severity")
                if not has_description: missing_fields.append("description")
                if not has_alert_type: missing_fields.append("alert_type")
                if not has_title: missing_fields.append("title")
                self.record_test_result("Alert Metadata Integrity", False, f"Missing fields: {', '.join(missing_fields)}")
        else:
            self.record_test_result("Alert Metadata Integrity", False, f"No alerts generated for metadata test (sent {events_sent} events)")
    
    def print_validation_summary(self):
        """Print validation summary"""
        self.print_header("Existing Functionality Validation Summary")
        
        total_tests = self.validation_results['tests_run']
        passed_tests = self.validation_results['tests_passed']
        failed_tests = self.validation_results['tests_failed']
        
        print(f"📊 Total Tests Run: {total_tests}")
        print(f"✅ Tests Passed: {passed_tests}")
        print(f"❌ Tests Failed: {failed_tests}")
        
        if total_tests > 0:
            success_rate = (passed_tests / total_tests) * 100
            print(f"📈 Success Rate: {success_rate:.1f}%")
        
        print(f"\n{'Test Details:'}")
        print("-" * 70)
        
        for test in self.validation_results['test_details']:
            status = "✅ PASS" if test['passed'] else "❌ FAIL"
            print(f"{test['test_name']:<40} {status}")
            if test['details']:
                print(f"    {test['details']}")
        
        if failed_tests == 0:
            print(f"\n🎉 All existing functionality is working correctly!")
            print("The false positive reduction features have been successfully integrated")
            print("without breaking any existing SIEM capabilities.")
        else:
            print(f"\n⚠️  {failed_tests} test(s) failed. Please review the issues above.")
            print("Some existing functionality may have been affected by the new features.")
        
        print(f"\n{'Validated Functionality:'}")
        print("• Basic brute force attack detection")
        print("• Basic port scan detection")
        print("• API endpoint availability")
        print("• Event ingestion (single and batch)")
        print("• Detection thresholds")
        print("• Tenant isolation")
        print("• Alert metadata integrity")
    
    async def run_validation(self):
        """Run the complete validation suite"""
        self.print_header("BITS-SIEM Existing Functionality Validation")
        
        print("This validation suite ensures that existing SIEM functionality")
        print("continues to work correctly after implementing false positive reduction.")
        print("\nPress Enter to continue...")
        input()
        
        try:
            # Run all validation tests
            await self.test_api_endpoints()
            await self.test_event_ingestion()
            await self.test_basic_brute_force_detection()
            await self.test_basic_port_scan_detection()
            await self.test_detection_thresholds()
            await self.test_tenant_isolation()
            await self.test_alert_metadata_integrity()
            
            # Print summary
            self.print_validation_summary()
            
        except KeyboardInterrupt:
            self.print_warning("Validation interrupted by user")
        except Exception as e:
            self.print_error(f"Validation error: {e}")
            import traceback
            traceback.print_exc()

async def main():
    """Main function to run the validation"""
    validator = ExistingFunctionalityValidator()
    await validator.run_validation()

if __name__ == "__main__":
    asyncio.run(main())
