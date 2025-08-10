#!/usr/bin/env python3
"""
Quick debug test to see processing service activity
"""

import socket
import time
from datetime import datetime

def send_single_auth_failure():
    """Send one authentication failure message"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    # Create SSH authentication failure message
    message_content = f"Failed password for debuguser from 192.168.1.200 port 22 ssh2"
    
    # RFC 5424 syslog format
    syslog_message = f"<84>1 {timestamp} server01 sshd 12345 - " + \
                    f'[meta tenant_id="demo-org" event_type="authentication_failure"] {message_content}'
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(syslog_message.encode('utf-8'), ("localhost", 514))
        sock.close()
        print(f"✅ Sent auth failure message: {message_content}")
        return True
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Quick Debug Test - Sending Single Auth Failure")
    print("=" * 50)
    
    # Send one message
    success = send_single_auth_failure()
    
    if success:
        print("\n⏰ Waiting 10 seconds for processing...")
        time.sleep(10)
        print("\n📋 Check processing service logs:")
        print("docker logs bits-siem-processing-1 --tail 20")
    else:
        print("\n❌ Failed to send test message")
