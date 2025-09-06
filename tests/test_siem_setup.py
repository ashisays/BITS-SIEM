#!/usr/bin/env python3
"""
Test script for SIEM Setup functionality
Tests tenant configuration and setup guide endpoints
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000/api"
TEST_EMAIL = "admin@acme.com"

# Get password from configuration manager
try:
    from config import config
    tenant_configs = config.get_sample_tenant_configs()
    TEST_PASSWORD = tenant_configs['acme-corp']['password']
    print(f"Using generated password for {TEST_EMAIL}: {TEST_PASSWORD}")
except ImportError:
    # Fallback password if config module is not available
    TEST_PASSWORD = "admin123"
    print(f"Using fallback password for {TEST_EMAIL}: {TEST_PASSWORD}")

def login():
    """Login and get JWT token"""
    try:
        response = requests.post(f"{BASE_URL}/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        
        if response.status_code == 200:
            data = response.json()
            return data.get("access_token"), data.get("csrf_token")
        else:
            print(f"Login failed: {response.status_code} - {response.text}")
            return None, None
    except Exception as e:
        print(f"Login error: {e}")
        return None, None

def make_authenticated_request(endpoint, method="GET", data=None, token=None, csrf_token=None):
    """Make authenticated request to API"""
    headers = {
        "Content-Type": "application/json"
    }
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    if csrf_token and method in ["POST", "PUT", "PATCH", "DELETE"]:
        headers["X-CSRF-Token"] = csrf_token
    
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            print(f"Unsupported method: {method}")
            return None
            
        return response
    except Exception as e:
        print(f"Request error: {e}")
        return None

def test_tenant_config(token, csrf_token):
    """Test tenant configuration endpoints"""
    print("\n" + "="*50)
    print("Testing Tenant Configuration")
    print("="*50)
    
    # Test GET tenant config
    print("\n1. Getting current tenant configuration...")
    response = make_authenticated_request("/tenant/config", "GET", token=token)
    
    if response and response.status_code == 200:
        config = response.json()
        print("✅ Current configuration retrieved successfully")
        print(f"   Server: {config.get('siem_server_ip')}:{config.get('siem_server_port')}")
        print(f"   Protocol: {config.get('siem_protocol')}")
        print(f"   Format: {config.get('syslog_format')}")
        print(f"   Status: {'Active' if config.get('enabled') else 'Inactive'}")
    else:
        print(f"❌ Failed to get configuration: {response.status_code if response else 'No response'}")
        return False
    
    # Test UPDATE tenant config
    print("\n2. Updating tenant configuration...")
    new_config = {
        "siem_server_ip": "192.168.1.200",
        "siem_server_port": 515,
        "siem_protocol": "tcp",
        "syslog_format": "rfc5424",
        "facility": "local1",
        "severity": "warning",
        "enabled": True,
        "setup_instructions": "Updated configuration for testing purposes."
    }
    
    response = make_authenticated_request("/tenant/config", "PUT", data=new_config, token=token, csrf_token=csrf_token)
    
    if response and response.status_code == 200:
        updated_config = response.json()
        print("✅ Configuration updated successfully")
        print(f"   New Server: {updated_config.get('siem_server_ip')}:{updated_config.get('siem_server_port')}")
        print(f"   New Protocol: {updated_config.get('siem_protocol')}")
        print(f"   New Format: {updated_config.get('syslog_format')}")
    else:
        print(f"❌ Failed to update configuration: {response.status_code if response else 'No response'}")
        if response:
            print(f"   Error: {response.text}")
        return False
    
    return True

def test_setup_guide(token):
    """Test setup guide endpoint"""
    print("\n" + "="*50)
    print("Testing Setup Guide")
    print("="*50)
    
    print("\n1. Getting setup guide...")
    response = make_authenticated_request("/tenant/setup-guide", "GET", token=token)
    
    if response and response.status_code == 200:
        guide = response.json()
        print("✅ Setup guide retrieved successfully")
        print(f"   Tenant ID: {guide.get('tenant_id')}")
        print(f"   Steps: {len(guide.get('setup_steps', []))}")
        print(f"   Supported Formats: {len(guide.get('supported_formats', []))}")
        print(f"   Troubleshooting Items: {len(guide.get('troubleshooting', []))}")
        
        # Display first step
        if guide.get('setup_steps'):
            first_step = guide['setup_steps'][0]
            print(f"\n   First Step: {first_step.get('title')}")
            print(f"   Description: {first_step.get('description')}")
        
        # Display configuration examples
        siem_config = guide.get('siem_config', {})
        if siem_config:
            print(f"\n   SIEM Configuration:")
            print(f"     Server: {siem_config.get('siem_server_ip')}:{siem_config.get('siem_server_port')}")
            print(f"     Protocol: {siem_config.get('siem_protocol')}")
            print(f"     Format: {siem_config.get('syslog_format')}")
        
    else:
        print(f"❌ Failed to get setup guide: {response.status_code if response else 'No response'}")
        if response:
            print(f"   Error: {response.text}")
        return False
    
    return True

def test_syslog_examples(token):
    """Test syslog message examples"""
    print("\n" + "="*50)
    print("Testing Syslog Examples")
    print("="*50)
    
    # Get current config for examples
    response = make_authenticated_request("/tenant/config", "GET", token=token)
    if not response or response.status_code != 200:
        print("❌ Cannot get configuration for examples")
        return False
    
    config = response.json()
    server_ip = config.get('siem_server_ip')
    server_port = config.get('siem_server_port')
    protocol = config.get('siem_protocol')
    
    print(f"\nCurrent SIEM Server: {server_ip}:{server_port} ({protocol.upper()})")
    
    # Example syslog messages
    examples = [
        {
            "name": "RFC 3164",
            "message": "<134>Jan 15 10:30:00 testhost testapp: Test message from BITS-SIEM"
        },
        {
            "name": "RFC 5424", 
            "message": "<134>1 2024-01-15T10:30:00.000Z testhost testapp 12345 - - Test message from BITS-SIEM"
        },
        {
            "name": "Cisco ASA",
            "message": "%ASA-6-106100: access-list ACL-INFRA-01 permitted tcp inside/192.168.1.100(12345) -> outside/203.0.113.1(80) hit-cnt 1 first hit [0x12345678, 0x0]"
        }
    ]
    
    print("\nExample syslog messages you can send:")
    for example in examples:
        print(f"\n{example['name']}:")
        print(f"  {example['message']}")
        print(f"  Command: echo '{example['message']}' | nc -u {server_ip} {server_port}")
    
    print(f"\nTest connectivity:")
    print(f"  telnet {server_ip} {server_port}")
    print(f"  nc -u {server_ip} {server_port}")
    
    return True

def main():
    """Main test function"""
    print("BITS-SIEM Setup Test Script")
    print("="*50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"API Base URL: {BASE_URL}")
    print(f"Test User: {TEST_EMAIL}")
    
    # Login
    print("\n1. Logging in...")
    token, csrf_token = login()
    
    if not token:
        print("❌ Login failed. Cannot proceed with tests.")
        sys.exit(1)
    
    print("✅ Login successful")
    print(f"   JWT Token: {token[:20]}...")
    print(f"   CSRF Token: {csrf_token[:20] if csrf_token else 'None'}...")
    
    # Run tests
    success_count = 0
    total_tests = 3
    
    if test_tenant_config(token, csrf_token):
        success_count += 1
    
    if test_setup_guide(token):
        success_count += 1
    
    if test_syslog_examples(token):
        success_count += 1
    
    # Summary
    print("\n" + "="*50)
    print("Test Summary")
    print("="*50)
    print(f"Tests Passed: {success_count}/{total_tests}")
    
    if success_count == total_tests:
        print("🎉 All tests passed! SIEM setup functionality is working correctly.")
        print("\nNext steps:")
        print("1. Access the SIEM Setup page in the dashboard")
        print("2. Configure your devices to send syslog to the specified server")
        print("3. Monitor the dashboard for incoming events")
    else:
        print("⚠️  Some tests failed. Please check the API and database configuration.")
        sys.exit(1)

if __name__ == "__main__":
    main() 