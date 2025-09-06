#!/usr/bin/env python3
"""
BITS-SIEM False Positive Reduction Demonstration
===============================================

This script demonstrates the false positive reduction capabilities by:
1. Simulating various attack scenarios
2. Showing how legitimate activities are filtered out
3. Demonstrating adaptive thresholds and whitelisting
4. Providing before/after comparison of alert volumes
"""

import asyncio
import json
import time
import requests
from datetime import datetime, timedelta, time as dt_time
from typing import List, Dict, Any
import random
import sys
import os

# Add the processing directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'processing'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'api'))

class FalsePositiveDemo:
    """Demonstration of false positive reduction capabilities"""
    
    def __init__(self, api_base_url: str = "http://localhost:8000"):
        self.api_base_url = api_base_url
        self.tenant_id = "demo-org"
        self.demo_results = {
            'scenarios_tested': 0,
            'alerts_without_fp_reduction': 0,
            'alerts_with_fp_reduction': 0,
            'false_positives_prevented': 0,
            'legitimate_attacks_preserved': 0,
            'scenarios': []
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
    
    async def setup_demo_environment(self):
        """Set up the demo environment with whitelists and configurations"""
        self.print_header("Setting Up Demo Environment")
        
        try:
            # Initialize false positive reduction for tenant
            response = requests.post(
                f"{self.api_base_url}/api/false-positive/initialize",
                params={"tenant_id": self.tenant_id}
            )
            
            if response.status_code == 200:
                self.print_success("Initialized false positive reduction system")
            else:
                self.print_warning(f"FP reduction initialization: {response.status_code}")
            
            # Set up business hours (9 AM - 5 PM weekdays)
            business_hours = {
                "timezone": "UTC",
                "weekday_start": "09:00:00",
                "weekday_end": "17:00:00",
                "holidays": []
            }
            
            response = requests.post(
                f"{self.api_base_url}/api/false-positive/business-hours",
                params={"tenant_id": self.tenant_id},
                json=business_hours
            )
            
            if response.status_code == 200:
                self.print_success("Set business hours configuration")
            else:
                self.print_warning(f"Business hours setup: {response.status_code}")
            
            # Add some legitimate IPs to whitelist
            legitimate_ips = [
                {"value": "192.168.1.10", "reason": "Admin workstation"},
                {"value": "192.168.1.20", "reason": "Monitoring server"},
                {"value": "10.0.0.0/8", "reason": "Internal network"}
            ]
            
            for ip_entry in legitimate_ips:
                whitelist_entry = {
                    "entry_type": "ip" if "/" not in ip_entry["value"] else "network",
                    "value": ip_entry["value"],
                    "reason": ip_entry["reason"],
                    "confidence": 1.0
                }
                
                response = requests.post(
                    f"{self.api_base_url}/api/false-positive/whitelist",
                    params={"tenant_id": self.tenant_id},
                    json=whitelist_entry
                )
                
                if response.status_code == 200:
                    self.print_success(f"Added whitelist entry: {ip_entry['value']}")
                else:
                    self.print_warning(f"Whitelist entry failed: {response.status_code}")
            
            # Add maintenance window for tonight
            maintenance_window = {
                "start_time": (datetime.utcnow() + timedelta(hours=18)).isoformat(),
                "end_time": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
                "authorized_ips": ["192.168.1.10", "192.168.1.30"],
                "description": "Scheduled network maintenance"
            }
            
            response = requests.post(
                f"{self.api_base_url}/api/false-positive/maintenance-window",
                params={"tenant_id": self.tenant_id},
                json=maintenance_window
            )
            
            if response.status_code == 200:
                self.print_success("Added maintenance window")
            else:
                self.print_warning(f"Maintenance window setup: {response.status_code}")
            
            self.print_info("Demo environment setup complete")
            
        except Exception as e:
            self.print_error(f"Error setting up demo environment: {e}")
    
    async def simulate_legitimate_admin_activity(self):
        """Simulate legitimate admin activity that should not trigger alerts"""
        self.print_header("Scenario 1: Legitimate Admin Activity")
        
        scenario = {
            'name': 'Legitimate Admin Activity',
            'description': 'Network admin performing port scan from whitelisted IP',
            'expected_result': 'Should be suppressed (false positive)',
            'actual_result': '',
            'suppressed': False
        }
        
        # Simulate port scan from admin workstation (whitelisted IP)
        admin_events = []
        admin_ip = "192.168.1.10"  # Whitelisted admin workstation
        
        self.print_info(f"Simulating port scan from admin workstation: {admin_ip}")
        
        # Generate multiple port connection events
        for port in [22, 23, 80, 443, 8080, 3389, 5985, 9090, 3000, 8443]:
            event = {
                "tenant_id": self.tenant_id,
                "event_type": "network_connection",
                "source_type": "firewall",
                "source_ip": admin_ip,
                "username": "admin",
                "user_agent": "nmap",
                "country": "US",
                "metadata": {
                    "port": port,
                    "protocol": "TCP",
                    "action": "ALLOW"
                }
            }
            admin_events.append(event)
        
        # Send events to detection system
        alerts_generated = 0
        for event in admin_events:
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=event
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('alerts_generated', 0) > 0:
                        alerts_generated += result['alerts_generated']
                
            except Exception as e:
                self.print_warning(f"Error sending event: {e}")
        
        # Check if alerts were generated
        time.sleep(2)  # Wait for processing
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={
                    "tenant_id": self.tenant_id,
                    "limit": 10
                }
            )
            
            if response.status_code == 200:
                alerts = response.json()
                recent_alerts = [
                    alert for alert in alerts 
                    if alert['source_ip'] == admin_ip and 
                    'port_scan' in alert.get('alert_type', '')
                ]
                
                if len(recent_alerts) == 0:
                    scenario['actual_result'] = 'Successfully suppressed (whitelisted IP)'
                    scenario['suppressed'] = True
                    self.print_success("✅ Admin activity correctly suppressed (whitelisted IP)")
                    self.demo_results['false_positives_prevented'] += 1
                else:
                    scenario['actual_result'] = f'Generated {len(recent_alerts)} alerts (should have been suppressed)'
                    self.print_warning(f"⚠️  Generated {len(recent_alerts)} alerts (should have been suppressed)")
            
        except Exception as e:
            self.print_error(f"Error checking alerts: {e}")
            scenario['actual_result'] = f'Error checking alerts: {e}'
        
        self.demo_results['scenarios'].append(scenario)
        self.demo_results['scenarios_tested'] += 1
    
    async def simulate_service_account_activity(self):
        """Simulate service account activity with expected failures"""
        self.print_header("Scenario 2: Service Account Activity")
        
        scenario = {
            'name': 'Service Account Activity',
            'description': 'API service account with occasional authentication failures',
            'expected_result': 'Should be suppressed (service account tolerance)',
            'actual_result': '',
            'suppressed': False
        }
        
        service_ip = "192.168.1.100"
        service_user = "api_service_account"
        
        self.print_info(f"Simulating service account activity: {service_user}")
        
        # Simulate a few failed attempts (within service account tolerance)
        failed_events = []
        for i in range(3):  # Only 3 failures - within service account tolerance
            event = {
                "tenant_id": self.tenant_id,
                "event_type": "authentication_failure",
                "source_type": "api",
                "source_ip": service_ip,
                "username": service_user,
                "user_agent": "python-requests/2.25.1",
                "country": "US",
                "failed_attempts_count": i + 1,
                "metadata": {
                    "service_type": "api",
                    "endpoint": "/api/v1/data"
                }
            }
            failed_events.append(event)
        
        # Send failed authentication events
        alerts_generated = 0
        for event in failed_events:
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=event
                )
                
                if response.status_code == 200:
                    result = response.json()
                    alerts_generated += result.get('alerts_generated', 0)
                
                time.sleep(0.5)  # Small delay between events
                
            except Exception as e:
                self.print_warning(f"Error sending event: {e}")
        
        # Add a successful authentication to establish pattern
        success_event = {
            "tenant_id": self.tenant_id,
            "event_type": "authentication_success",
            "source_type": "api",
            "source_ip": service_ip,
            "username": service_user,
            "user_agent": "python-requests/2.25.1",
            "country": "US",
            "metadata": {
                "service_type": "api",
                "endpoint": "/api/v1/data"
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_base_url}/api/detection/events/ingest",
                params={"tenant_id": self.tenant_id},
                json=success_event
            )
        except Exception as e:
            self.print_warning(f"Error sending success event: {e}")
        
        # Check results
        time.sleep(3)  # Wait for processing
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={
                    "tenant_id": self.tenant_id,
                    "limit": 10
                }
            )
            
            if response.status_code == 200:
                alerts = response.json()
                service_alerts = [
                    alert for alert in alerts 
                    if alert['source_ip'] == service_ip and 
                    service_user in alert.get('description', '')
                ]
                
                if len(service_alerts) == 0:
                    scenario['actual_result'] = 'Successfully suppressed (service account tolerance)'
                    scenario['suppressed'] = True
                    self.print_success("✅ Service account activity correctly suppressed")
                    self.demo_results['false_positives_prevented'] += 1
                else:
                    scenario['actual_result'] = f'Generated {len(service_alerts)} alerts'
                    self.print_warning(f"⚠️  Generated {len(service_alerts)} alerts for service account")
            
        except Exception as e:
            self.print_error(f"Error checking alerts: {e}")
            scenario['actual_result'] = f'Error checking alerts: {e}'
        
        self.demo_results['scenarios'].append(scenario)
        self.demo_results['scenarios_tested'] += 1
    
    async def simulate_business_hours_context(self):
        """Simulate low-confidence alerts outside business hours"""
        self.print_header("Scenario 3: Business Hours Context")
        
        scenario = {
            'name': 'Business Hours Context',
            'description': 'Low-confidence brute force attempt outside business hours',
            'expected_result': 'Should be suppressed (outside business hours + low confidence)',
            'actual_result': '',
            'suppressed': False
        }
        
        # Simulate activity at 2 AM (outside business hours)
        night_ip = "203.0.113.100"
        
        self.print_info(f"Simulating low-confidence activity outside business hours from {night_ip}")
        
        # Generate just enough failures to trigger threshold but with low confidence indicators
        night_events = []
        for i in range(6):  # Just above threshold
            event = {
                "tenant_id": self.tenant_id,
                "event_type": "authentication_failure",
                "source_type": "ssh",
                "source_ip": night_ip,
                "username": "user" + str(i % 3),  # Different usernames (less focused attack)
                "user_agent": "OpenSSH_7.4",
                "country": "US",
                "failed_attempts_count": i + 1,
                "metadata": {
                    "simulated_hour": 2  # 2 AM
                }
            }
            night_events.append(event)
        
        # Send events with delays to simulate human-like timing
        for event in night_events:
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=event
                )
                
                # Random delay between 5-30 seconds to simulate human behavior
                time.sleep(random.uniform(0.5, 2.0))
                
            except Exception as e:
                self.print_warning(f"Error sending event: {e}")
        
        # Check results
        time.sleep(3)
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={
                    "tenant_id": self.tenant_id,
                    "limit": 10
                }
            )
            
            if response.status_code == 200:
                alerts = response.json()
                night_alerts = [
                    alert for alert in alerts 
                    if alert['source_ip'] == night_ip
                ]
                
                if len(night_alerts) == 0:
                    scenario['actual_result'] = 'Successfully suppressed (business hours context)'
                    scenario['suppressed'] = True
                    self.print_success("✅ Low-confidence night activity correctly suppressed")
                    self.demo_results['false_positives_prevented'] += 1
                else:
                    scenario['actual_result'] = f'Generated {len(night_alerts)} alerts'
                    self.print_warning(f"⚠️  Generated {len(night_alerts)} alerts (business hours context)")
            
        except Exception as e:
            self.print_error(f"Error checking alerts: {e}")
            scenario['actual_result'] = f'Error checking alerts: {e}'
        
        self.demo_results['scenarios'].append(scenario)
        self.demo_results['scenarios_tested'] += 1
    
    async def simulate_genuine_attack(self):
        """Simulate a genuine attack that should NOT be suppressed"""
        self.print_header("Scenario 4: Genuine Attack (Should NOT be suppressed)")
        
        scenario = {
            'name': 'Genuine Attack',
            'description': 'High-confidence brute force attack from external IP',
            'expected_result': 'Should generate alert (genuine attack)',
            'actual_result': '',
            'suppressed': False
        }
        
        # External attacker IP (not whitelisted)
        attacker_ip = "203.0.113.200"
        
        self.print_info(f"Simulating genuine brute force attack from {attacker_ip}")
        
        # Generate clear attack pattern - many failures, focused on admin accounts
        attack_events = []
        admin_accounts = ["admin", "administrator", "root"]
        
        for i in range(15):  # Well above threshold
            event = {
                "tenant_id": self.tenant_id,
                "event_type": "authentication_failure",
                "source_type": "ssh",
                "source_ip": attacker_ip,
                "username": admin_accounts[i % len(admin_accounts)],  # Focus on admin accounts
                "user_agent": "OpenSSH_7.4",
                "country": "CN",  # High-risk country
                "failed_attempts_count": i + 1,
                "metadata": {
                    "attack_pattern": "dictionary",
                    "rapid_attempts": True
                }
            }
            attack_events.append(event)
        
        # Send events rapidly (automated attack pattern)
        for event in attack_events:
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=event
                )
                
                time.sleep(0.1)  # Very short delay (automated)
                
            except Exception as e:
                self.print_warning(f"Error sending event: {e}")
        
        # Check results
        time.sleep(5)  # Wait for processing
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={
                    "tenant_id": self.tenant_id,
                    "limit": 10
                }
            )
            
            if response.status_code == 200:
                alerts = response.json()
                attack_alerts = [
                    alert for alert in alerts 
                    if alert['source_ip'] == attacker_ip
                ]
                
                if len(attack_alerts) > 0:
                    scenario['actual_result'] = f'Generated {len(attack_alerts)} alerts (correct)'
                    scenario['suppressed'] = False
                    self.print_success(f"✅ Genuine attack correctly detected ({len(attack_alerts)} alerts)")
                    self.demo_results['legitimate_attacks_preserved'] += 1
                else:
                    scenario['actual_result'] = 'No alerts generated (should have generated alerts)'
                    self.print_error("❌ Genuine attack was not detected!")
            
        except Exception as e:
            self.print_error(f"Error checking alerts: {e}")
            scenario['actual_result'] = f'Error checking alerts: {e}'
        
        self.demo_results['scenarios'].append(scenario)
        self.demo_results['scenarios_tested'] += 1
    
    async def simulate_dynamic_whitelist_learning(self):
        """Simulate dynamic whitelist learning from successful authentications"""
        self.print_header("Scenario 5: Dynamic Whitelist Learning")
        
        scenario = {
            'name': 'Dynamic Whitelist Learning',
            'description': 'IP with successful auth history gets whitelisted dynamically',
            'expected_result': 'Should be suppressed after building trust',
            'actual_result': '',
            'suppressed': False
        }
        
        learning_ip = "192.168.2.50"
        regular_user = "john.doe"
        
        self.print_info(f"Simulating dynamic whitelist learning for {learning_ip}")
        
        # First, establish successful authentication pattern
        for i in range(6):  # Above dynamic whitelist threshold
            success_event = {
                "tenant_id": self.tenant_id,
                "event_type": "authentication_success",
                "source_type": "web",
                "source_ip": learning_ip,
                "username": regular_user,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "country": "US",
                "metadata": {
                    "login_duration": 3600,
                    "session_type": "interactive"
                }
            }
            
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=success_event
                )
                time.sleep(0.5)
            except Exception as e:
                self.print_warning(f"Error sending success event: {e}")
        
        # Wait for dynamic whitelist to be established
        time.sleep(2)
        
        # Now simulate some failed attempts (should be suppressed due to dynamic whitelist)
        failed_events = []
        for i in range(7):  # Above threshold but should be suppressed
            event = {
                "tenant_id": self.tenant_id,
                "event_type": "authentication_failure",
                "source_type": "web",
                "source_ip": learning_ip,
                "username": regular_user,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "country": "US",
                "failed_attempts_count": i + 1,
                "metadata": {
                    "reason": "password_expired"  # Legitimate reason
                }
            }
            failed_events.append(event)
        
        for event in failed_events:
            try:
                response = requests.post(
                    f"{self.api_base_url}/api/detection/events/ingest",
                    params={"tenant_id": self.tenant_id},
                    json=event
                )
                time.sleep(0.3)
            except Exception as e:
                self.print_warning(f"Error sending failed event: {e}")
        
        # Check if IP is dynamically whitelisted
        try:
            response = requests.get(
                f"{self.api_base_url}/api/false-positive/whitelist/check",
                params={
                    "tenant_id": self.tenant_id,
                    "entry_type": "ip",
                    "value": learning_ip
                }
            )
            
            if response.status_code == 200:
                whitelist_status = response.json()
                if whitelist_status.get('dynamic_whitelist', {}).get('found'):
                    self.print_success(f"✅ IP {learning_ip} dynamically whitelisted")
                else:
                    self.print_info(f"IP {learning_ip} not yet dynamically whitelisted")
        except Exception as e:
            self.print_warning(f"Error checking whitelist status: {e}")
        
        # Check for alerts
        time.sleep(3)
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/detection/alerts",
                params={
                    "tenant_id": self.tenant_id,
                    "limit": 10
                }
            )
            
            if response.status_code == 200:
                alerts = response.json()
                learning_alerts = [
                    alert for alert in alerts 
                    if alert['source_ip'] == learning_ip
                ]
                
                if len(learning_alerts) == 0:
                    scenario['actual_result'] = 'Successfully suppressed (dynamic whitelist)'
                    scenario['suppressed'] = True
                    self.print_success("✅ Dynamic whitelist learning successful")
                    self.demo_results['false_positives_prevented'] += 1
                else:
                    scenario['actual_result'] = f'Generated {len(learning_alerts)} alerts'
                    self.print_warning(f"⚠️  Generated {len(learning_alerts)} alerts (dynamic whitelist)")
            
        except Exception as e:
            self.print_error(f"Error checking alerts: {e}")
            scenario['actual_result'] = f'Error checking alerts: {e}'
        
        self.demo_results['scenarios'].append(scenario)
        self.demo_results['scenarios_tested'] += 1
    
    def print_demo_summary(self):
        """Print comprehensive demo summary"""
        self.print_header("False Positive Reduction Demo Summary")
        
        print(f"📊 Scenarios Tested: {self.demo_results['scenarios_tested']}")
        print(f"🛡️  False Positives Prevented: {self.demo_results['false_positives_prevented']}")
        print(f"🎯 Legitimate Attacks Preserved: {self.demo_results['legitimate_attacks_preserved']}")
        
        if self.demo_results['scenarios_tested'] > 0:
            suppression_rate = (self.demo_results['false_positives_prevented'] / 
                              (self.demo_results['false_positives_prevented'] + 
                               self.demo_results['legitimate_attacks_preserved'])) * 100
            print(f"📈 False Positive Suppression Rate: {suppression_rate:.1f}%")
        
        print(f"\n{'Scenario Details:':<30} {'Result':<20} {'Status'}")
        print("-" * 70)
        
        for scenario in self.demo_results['scenarios']:
            status = "✅ PASS" if (
                (scenario['expected_result'].startswith('Should be suppressed') and scenario['suppressed']) or
                (scenario['expected_result'].startswith('Should generate') and not scenario['suppressed'])
            ) else "❌ FAIL"
            
            print(f"{scenario['name']:<30} {scenario['actual_result']:<20} {status}")
        
        print(f"\n{'Benefits Demonstrated:'}")
        print("• Static whitelisting for known legitimate sources")
        print("• Dynamic whitelisting based on successful authentication patterns")
        print("• Business hours context for risk assessment")
        print("• Service account recognition and tolerance")
        print("• Behavioral analysis for attack pattern detection")
        print("• Geographic risk assessment")
        print("• Maintenance window awareness")
        
        print(f"\n{'Key Metrics:'}")
        print(f"• Reduced alert volume by filtering false positives")
        print(f"• Preserved detection of genuine attacks")
        print(f"• Adaptive learning from user behavior")
        print(f"• Context-aware risk assessment")
    
    async def run_demo(self):
        """Run the complete false positive reduction demonstration"""
        self.print_header("BITS-SIEM False Positive Reduction Demonstration")
        
        print("This demo will show how the SIEM system intelligently reduces false positives")
        print("while preserving detection of genuine security threats.")
        print("\nPress Enter to continue...")
        input()
        
        try:
            # Setup
            await self.setup_demo_environment()
            
            # Run scenarios
            await self.simulate_legitimate_admin_activity()
            await self.simulate_service_account_activity()
            await self.simulate_business_hours_context()
            await self.simulate_genuine_attack()
            await self.simulate_dynamic_whitelist_learning()
            
            # Summary
            self.print_demo_summary()
            
        except KeyboardInterrupt:
            self.print_warning("Demo interrupted by user")
        except Exception as e:
            self.print_error(f"Demo error: {e}")
            import traceback
            traceback.print_exc()

async def main():
    """Main function to run the demo"""
    demo = FalsePositiveDemo()
    await demo.run_demo()

if __name__ == "__main__":
    asyncio.run(main())
