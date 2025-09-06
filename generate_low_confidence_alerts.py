#!/usr/bin/env python3
"""
Generate low confidence alerts for testing the new warning functionality
"""

import requests
import json
import time
from datetime import datetime

def create_low_confidence_alert():
    """Create a low confidence alert directly via the API"""
    
    # Simulate a low confidence brute force attempt (just 3 attempts)
    alert_data = {
        "tenant_id": "demo-org",
        "alert_type": "brute_force_attack", 
        "title": "Potential Brute Force Activity",
        "description": "Detected 3 failed login attempts from 203.0.113.100 within 300 seconds (Low confidence: 30%)",
        "severity": "warning",
        "confidence_score": 0.3,
        "username": "testuser",
        "source_ip": "203.0.113.100",
        "affected_systems": ["203.0.113.100"],
        "status": "open",
        "correlation_data": {
            "detection_engine": "brute_force",
            "confidence_reason": "Low attempt count, may be legitimate user error"
        }
    }
    
    try:
        # Try to post directly to the database via API
        response = requests.post(
            "http://localhost:8000/api/detection/events/ingest",
            json={
                "tenant_id": "demo-org",
                "username": "testuser",
                "event_type": "login_failure", 
                "source_type": "web",
                "source_ip": "203.0.113.100",
                "failed_attempts_count": 3,
                "metadata": {"confidence": 0.3}
            }
        )
        print(f"Low confidence alert created: {response.status_code}")
        
        # Create another one with different IP
        response2 = requests.post(
            "http://localhost:8000/api/detection/events/ingest",
            json={
                "tenant_id": "demo-org", 
                "username": "admin",
                "event_type": "login_failure",
                "source_type": "ssh",
                "source_ip": "203.0.113.101", 
                "failed_attempts_count": 2,
                "metadata": {"confidence": 0.4}
            }
        )
        print(f"Second low confidence alert created: {response2.status_code}")
        
    except Exception as e:
        print(f"Error creating alerts: {e}")

if __name__ == "__main__":
    print("Generating low confidence alerts for testing...")
    create_low_confidence_alert()
    print("Done! Check the dashboard to see the new warning alerts.")
