#!/usr/bin/env python3
"""
Simple WebSocket test for notification service
"""

import asyncio
import websockets
import json
import sys
import aiohttp
import time

async def send_notification():
    """Send a test notification"""
    url = "http://localhost:8001/notifications/send"
    data = {
        "id": "test-ws-notification",
        "tenant_id": "demo-org",
        "user_id": "admin@demo.com",
        "type": "security_alert",
        "severity": "critical",
        "title": "WebSocket Test Alert",
        "message": "This is a test alert for WebSocket notifications",
        "source_ip": "192.168.1.100",
        "created_at": "2025-08-29T04:35:00Z"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data) as response:
                result = await response.json()
                print(f"📤 Notification sent: {result}")
                return result.get('status') in ['success', 'partial_failure']
    except Exception as e:
        print(f"❌ Failed to send notification: {e}")
        return False

async def test_websocket():
    """Test WebSocket connection to notification service"""
    uri = "ws://localhost:8001/ws/notifications/demo-org"
    
    try:
        print(f"Connecting to {uri}...")
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully!")
            
            # Send a ping to test connection
            pong_waiter = await websocket.ping()
            await asyncio.wait_for(pong_waiter, timeout=5.0)
            print("✅ Ping/Pong test successful!")
            
            # Send a notification while connected
            print("Sending test notification...")
            notification_sent = await send_notification()
            
            if notification_sent:
                # Wait for the notification to be received
                print("Waiting for notification (5 seconds)...")
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    data = json.loads(message)
                    print(f"✅ Received notification: {data}")
                    return True
                except asyncio.TimeoutError:
                    print("❌ No notification received within timeout")
                    return False
            else:
                print("❌ Failed to send notification")
                return False
            
    except Exception as e:
        print(f"❌ WebSocket test failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_websocket())
    sys.exit(0 if success else 1)
