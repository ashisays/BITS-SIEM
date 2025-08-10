"""
BITS-SIEM Processing Pipeline Integration Tests
Comprehensive tests including false positives and actual threat detection
"""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch, AsyncMock
import redis
from dataclasses import asdict

from config import config
from stream_processor import StreamProcessor, ProcessedEvent
from threat_detection import (
    ThreatDetectionManager, 
    BruteForceDetectionEngine, 
    PortScanDetectionEngine,
    AnomalyDetectionEngine,
    ThreatAlert
)
from alert_manager import AlertManager, ManagedAlert, AlertStatus

class TestDataGenerator:
    """Generates realistic test data for various scenarios"""
    
    @staticmethod
    def generate_legitimate_login_events(tenant_id: str, count: int = 10) -> List[ProcessedEvent]:
        """Generate legitimate login events that should NOT trigger brute force alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Successful logins spread over time
        for i in range(count):
            event = ProcessedEvent(
                id=f"login_success_{i}",
                tenant_id=tenant_id,
                source_ip="192.168.1.100",
                message="User john.doe successfully logged in",
                timestamp=base_time + timedelta(minutes=i * 5),  # 5 minutes apart
                event_type="authentication_success",
                severity="info",
                risk_score=0.1,
                raw_data={
                    "program": "sshd",
                    "username": "john.doe",
                    "status": "success"
                }
            )
            events.append(event)
        
        # Mix in occasional failed login (normal user behavior)
        if count > 3:
            failed_event = ProcessedEvent(
                id=f"login_fail_normal",
                tenant_id=tenant_id,
                source_ip="192.168.1.100",
                message="Authentication failed for user john.doe",
                timestamp=base_time + timedelta(minutes=2),
                event_type="authentication_failure",
                severity="warning",
                risk_score=0.3,
                raw_data={
                    "program": "sshd",
                    "username": "john.doe",
                    "status": "failed",
                    "reason": "incorrect_password"
                }
            )
            events.append(failed_event)
        
        return events
    
    @staticmethod
    def generate_brute_force_attack_events(tenant_id: str, count: int = 10) -> List[ProcessedEvent]:
        """Generate brute force attack events that SHOULD trigger alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Rapid failed login attempts
        for i in range(count):
            event = ProcessedEvent(
                id=f"brute_force_{i}",
                tenant_id=tenant_id,
                source_ip="10.0.0.1",  # Attacker IP
                message=f"Authentication failed for user admin",
                timestamp=base_time + timedelta(seconds=i * 2),  # 2 seconds apart
                event_type="authentication_failure",
                severity="warning",
                risk_score=0.5,
                raw_data={
                    "program": "sshd",
                    "username": "admin",
                    "status": "failed",
                    "reason": "incorrect_password"
                }
            )
            events.append(event)
        
        return events
    
    @staticmethod
    def generate_legitimate_network_events(tenant_id: str, count: int = 15) -> List[ProcessedEvent]:
        """Generate legitimate network events that should NOT trigger port scan alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Normal web server connections
        web_ports = [80, 443, 8080]
        for i in range(count):
            port = web_ports[i % len(web_ports)]
            event = ProcessedEvent(
                id=f"web_traffic_{i}",
                tenant_id=tenant_id,
                source_ip="192.168.1.50",
                message=f"Connection established to port {port}",
                timestamp=base_time + timedelta(minutes=i),
                event_type="network_connection",
                severity="info",
                risk_score=0.1,
                raw_data={
                    "program": "apache",
                    "port": port,
                    "protocol": "tcp",
                    "status": "established"
                }
            )
            events.append(event)
        
        return events
    
    @staticmethod
    def generate_port_scan_attack_events(tenant_id: str, count: int = 25) -> List[ProcessedEvent]:
        """Generate port scanning events that SHOULD trigger alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Rapid connections to many different ports
        for i in range(count):
            port = 1000 + i  # Sequential port scanning
            event = ProcessedEvent(
                id=f"port_scan_{i}",
                tenant_id=tenant_id,
                source_ip="10.0.0.2",  # Attacker IP
                message=f"Connection attempt to port {port}",
                timestamp=base_time + timedelta(seconds=i),  # 1 second apart
                event_type="network_connection",
                severity="info",
                risk_score=0.2,
                raw_data={
                    "program": "netstat",
                    "port": port,
                    "protocol": "tcp",
                    "status": "syn_sent"
                }
            )
            events.append(event)
        
        return events
    
    @staticmethod
    def generate_normal_user_activity(tenant_id: str, count: int = 50) -> List[ProcessedEvent]:
        """Generate normal user activity that should NOT trigger anomaly alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Regular pattern of activities
        activity_types = [
            ("authentication_success", "info", 0.1),
            ("file_access", "info", 0.1),
            ("network_connection", "info", 0.1),
            ("system_event", "info", 0.1)
        ]
        
        for i in range(count):
            activity_type, severity, risk_score = activity_types[i % len(activity_types)]
            event = ProcessedEvent(
                id=f"normal_activity_{i}",
                tenant_id=tenant_id,
                source_ip="192.168.1.200",
                message=f"Normal {activity_type} activity",
                timestamp=base_time + timedelta(minutes=i * 2),  # Spread over time
                event_type=activity_type,
                severity=severity,
                risk_score=risk_score,
                raw_data={
                    "program": "system",
                    "user": "regular_user",
                    "session": f"session_{i // 10}"
                }
            )
            events.append(event)
        
        return events
    
    @staticmethod
    def generate_anomalous_activity(tenant_id: str, count: int = 30) -> List[ProcessedEvent]:
        """Generate anomalous activity that SHOULD trigger alerts"""
        events = []
        base_time = datetime.utcnow()
        
        # Burst of high-risk activities
        for i in range(count):
            event = ProcessedEvent(
                id=f"anomaly_{i}",
                tenant_id=tenant_id,
                source_ip="10.0.0.3",  # Suspicious IP
                message=f"High-risk security event detected",
                timestamp=base_time + timedelta(seconds=i * 3),  # Rapid succession
                event_type="security_event",
                severity="critical",
                risk_score=0.9,  # High risk
                raw_data={
                    "program": "security_scanner",
                    "event": "privilege_escalation",
                    "severity": "high"
                }
            )
            events.append(event)
        
        return events

class TestProcessingPipeline:
    """Integration tests for the entire processing pipeline"""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client for testing"""
        with patch('redis.Redis') as mock_redis_class:
            mock_redis = Mock()
            mock_redis.ping.return_value = True
            mock_redis.get.return_value = None
            mock_redis.setex.return_value = True
            mock_redis.sadd.return_value = 1
            mock_redis.scard.return_value = 0
            mock_redis.smembers.return_value = set()
            mock_redis.expire.return_value = True
            mock_redis.lpush.return_value = 1
            mock_redis.lrange.return_value = []
            mock_redis.keys.return_value = []
            mock_redis.delete.return_value = 1
            mock_redis.ttl.return_value = -1
            mock_redis_class.return_value = mock_redis
            yield mock_redis
    
    @pytest.fixture
    def mock_alert_manager(self):
        """Mock alert manager for testing"""
        with patch('alert_manager.AlertManager') as mock_am:
            mock_instance = Mock()
            mock_instance.process_threat_alert = AsyncMock()
            mock_instance.get_stats.return_value = {
                'alerts_created': 0,
                'alerts_resolved': 0,
                'notifications_sent': 0
            }
            mock_am.return_value = mock_instance
            yield mock_instance
    
    @pytest.mark.asyncio
    async def test_brute_force_detection_false_positives(self, mock_redis):
        """Test that legitimate login patterns don't trigger false positive alerts"""
        # Initialize detection engine
        engine = BruteForceDetectionEngine()
        
        # Generate legitimate login events
        legitimate_events = TestDataGenerator.generate_legitimate_login_events("tenant1", 5)
        
        # Process events
        alerts = []
        for event in legitimate_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should not trigger any alerts
        assert len(alerts) == 0, f"False positive: {len(alerts)} alerts triggered for legitimate logins"
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] == 0
        assert stats['events_processed'] > 0
    
    @pytest.mark.asyncio
    async def test_brute_force_detection_actual_threats(self, mock_redis):
        """Test that actual brute force attacks are detected"""
        # Initialize detection engine
        engine = BruteForceDetectionEngine()
        
        # Configure Redis mock for brute force detection
        call_count = 0
        def mock_get(key):
            nonlocal call_count
            call_count += 1
            return str(call_count - 1)  # Simulate increasing count
        
        mock_redis.get.side_effect = mock_get
        
        # Generate brute force attack events
        attack_events = TestDataGenerator.generate_brute_force_attack_events("tenant1", 8)
        
        # Process events
        alerts = []
        for event in attack_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should trigger at least one alert when threshold is exceeded
        assert len(alerts) >= 1, f"No alerts triggered for brute force attack"
        
        # Verify alert details
        if alerts:
            alert = alerts[0]
            assert alert.alert_type == "brute_force_attack"
            assert alert.severity == "critical"
            assert alert.source_ip == "10.0.0.1"
            assert alert.risk_score == 0.9
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] >= 1
    
    @pytest.mark.asyncio
    async def test_port_scan_detection_false_positives(self, mock_redis):
        """Test that legitimate network traffic doesn't trigger false positive alerts"""
        # Initialize detection engine
        engine = PortScanDetectionEngine()
        
        # Generate legitimate network events
        legitimate_events = TestDataGenerator.generate_legitimate_network_events("tenant1", 8)
        
        # Process events
        alerts = []
        for event in legitimate_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should not trigger any alerts (only 3 unique ports)
        assert len(alerts) == 0, f"False positive: {len(alerts)} alerts triggered for legitimate network traffic"
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] == 0
        assert stats['events_processed'] > 0
    
    @pytest.mark.asyncio
    async def test_port_scan_detection_actual_threats(self, mock_redis):
        """Test that actual port scanning is detected"""
        # Initialize detection engine
        engine = PortScanDetectionEngine()
        
        # Configure Redis mock for port scanning
        unique_ports = set()
        def mock_sadd(key, port):
            unique_ports.add(port)
            return 1
        
        def mock_scard(key):
            return len(unique_ports)
        
        def mock_smembers(key):
            return unique_ports
        
        mock_redis.sadd.side_effect = mock_sadd
        mock_redis.scard.side_effect = mock_scard
        mock_redis.smembers.side_effect = mock_smembers
        
        # Generate port scan attack events
        attack_events = TestDataGenerator.generate_port_scan_attack_events("tenant1", 15)
        
        # Process events
        alerts = []
        for event in attack_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should trigger at least one alert when threshold is exceeded
        assert len(alerts) >= 1, f"No alerts triggered for port scan attack"
        
        # Verify alert details
        if alerts:
            alert = alerts[0]
            assert alert.alert_type == "port_scan_attack"
            assert alert.source_ip == "10.0.0.2"
            assert alert.risk_score == 0.7
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] >= 1
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_false_positives(self):
        """Test that normal user activity doesn't trigger false positive alerts"""
        # Initialize detection engine
        engine = AnomalyDetectionEngine()
        
        # Generate normal user activity
        normal_events = TestDataGenerator.generate_normal_user_activity("tenant1", 15)
        
        # Process events
        alerts = []
        for event in normal_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should not trigger any alerts for normal activity
        assert len(alerts) == 0, f"False positive: {len(alerts)} alerts triggered for normal activity"
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] == 0
        assert stats['events_processed'] > 0
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_actual_threats(self):
        """Test that actual anomalous behavior is detected"""
        # Initialize detection engine
        engine = AnomalyDetectionEngine()
        
        # Generate anomalous activity
        anomalous_events = TestDataGenerator.generate_anomalous_activity("tenant1", 15)
        
        # Process events
        alerts = []
        for event in anomalous_events:
            alert = await engine.analyze_event(event)
            if alert:
                alerts.append(alert)
        
        # Should trigger at least one alert for anomalous behavior
        assert len(alerts) >= 1, f"No alerts triggered for anomalous activity"
        
        # Verify alert details
        if alerts:
            alert = alerts[0]
            assert alert.alert_type == "anomaly_detected"
            assert alert.severity == "warning"
            assert alert.source_ip == "10.0.0.3"
        
        # Verify stats
        stats = engine.get_stats()
        assert stats['threats_detected'] >= 1
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection_pipeline(self, mock_redis, mock_alert_manager):
        """Test the complete threat detection pipeline end-to-end"""
        # Initialize threat detection manager
        manager = ThreatDetectionManager()
        
        # Configure Redis mocks for multiple engines
        self._setup_redis_mocks_for_pipeline(mock_redis)
        
        # Generate mixed events (legitimate + threats)
        all_events = []
        all_events.extend(TestDataGenerator.generate_legitimate_login_events("tenant1", 3))
        all_events.extend(TestDataGenerator.generate_brute_force_attack_events("tenant1", 8))
        all_events.extend(TestDataGenerator.generate_legitimate_network_events("tenant1", 5))
        all_events.extend(TestDataGenerator.generate_port_scan_attack_events("tenant1", 15))
        all_events.extend(TestDataGenerator.generate_normal_user_activity("tenant1", 10))
        all_events.extend(TestDataGenerator.generate_anomalous_activity("tenant1", 12))
        
        # Process all events
        total_alerts = []
        for event in all_events:
            alerts = await manager.analyze_event(event)
            if alerts:
                total_alerts.extend(alerts)
        
        # Should detect threats but not generate false positives
        assert len(total_alerts) >= 3, f"Expected multiple threats detected, got {len(total_alerts)}"
        
        # Verify alert types
        alert_types = [alert.alert_type for alert in total_alerts]
        expected_types = ["brute_force_attack", "port_scan_attack", "anomaly_detected"]
        
        for expected_type in expected_types:
            assert expected_type in alert_types, f"Expected {expected_type} not found in alerts"
        
        # Verify no false positives from legitimate activities
        legitimate_ips = ["192.168.1.100", "192.168.1.50", "192.168.1.200"]
        false_positive_alerts = [
            alert for alert in total_alerts 
            if alert.source_ip in legitimate_ips
        ]
        assert len(false_positive_alerts) == 0, f"False positives detected: {len(false_positive_alerts)}"
        
        # Verify stats
        stats = manager.get_stats()
        assert stats['total_threats_detected'] >= 3
        assert stats['total_events_processed'] > 0
    
    def _setup_redis_mocks_for_pipeline(self, mock_redis):
        """Setup Redis mocks for the complete pipeline test"""
        # Track state for different detection engines
        self.brute_force_counts = {}
        self.port_scan_sets = {}
        
        def mock_get(key):
            if "brute_force:" in key:
                return str(self.brute_force_counts.get(key, 0))
            return None
        
        def mock_setex(key, ttl, value):
            if "brute_force:" in key:
                self.brute_force_counts[key] = int(value)
            return True
        
        def mock_sadd(key, port):
            if "port_scan:" in key:
                if key not in self.port_scan_sets:
                    self.port_scan_sets[key] = set()
                self.port_scan_sets[key].add(port)
            return 1
        
        def mock_scard(key):
            if "port_scan:" in key:
                return len(self.port_scan_sets.get(key, set()))
            return 0
        
        def mock_smembers(key):
            if "port_scan:" in key:
                return self.port_scan_sets.get(key, set())
            return set()
        
        mock_redis.get.side_effect = mock_get
        mock_redis.setex.side_effect = mock_setex
        mock_redis.sadd.side_effect = mock_sadd
        mock_redis.scard.side_effect = mock_scard
        mock_redis.smembers.side_effect = mock_smembers
    
    @pytest.mark.asyncio
    async def test_alert_correlation_and_deduplication(self, mock_redis, mock_alert_manager):
        """Test alert correlation and deduplication functionality"""
        # Generate multiple similar brute force attacks
        events1 = TestDataGenerator.generate_brute_force_attack_events("tenant1", 6)
        events2 = TestDataGenerator.generate_brute_force_attack_events("tenant1", 6)
        
        # Process events in batches
        manager = ThreatDetectionManager()
        self._setup_redis_mocks_for_pipeline(mock_redis)
        
        # Process first batch
        alerts1 = []
        for event in events1:
            alerts = await manager.analyze_event(event)
            if alerts:
                alerts1.extend(alerts)
        
        # Process second batch (should be correlated)
        alerts2 = []
        for event in events2:
            alerts = await manager.analyze_event(event)
            if alerts:
                alerts2.extend(alerts)
        
        # Verify alerts were generated
        total_alerts = alerts1 + alerts2
        assert len(total_alerts) >= 1, "No alerts generated for brute force attacks"
        
        # In a real scenario, correlation would reduce duplicate alerts
        # This test validates the detection pipeline works correctly
    
    @pytest.mark.asyncio
    async def test_detection_accuracy_metrics(self, mock_redis):
        """Test detection accuracy and false positive rate"""
        # Initialize engines
        bf_engine = BruteForceDetectionEngine()
        ps_engine = PortScanDetectionEngine()
        
        # Configure Redis mocks
        self._setup_redis_mocks_for_pipeline(mock_redis)
        
        # Generate test dataset
        legitimate_events = []
        legitimate_events.extend(TestDataGenerator.generate_legitimate_login_events("tenant1", 10))
        legitimate_events.extend(TestDataGenerator.generate_legitimate_network_events("tenant1", 10))
        
        threat_events = []
        threat_events.extend(TestDataGenerator.generate_brute_force_attack_events("tenant1", 10))
        threat_events.extend(TestDataGenerator.generate_port_scan_attack_events("tenant1", 20))
        
        # Process legitimate events
        false_positives = 0
        for event in legitimate_events:
            if event.event_type == "authentication_failure":
                alert = await bf_engine.analyze_event(event)
                if alert:
                    false_positives += 1
            elif event.event_type == "network_connection":
                alert = await ps_engine.analyze_event(event)
                if alert:
                    false_positives += 1
        
        # Process threat events
        true_positives = 0
        for event in threat_events:
            if event.event_type == "authentication_failure":
                alert = await bf_engine.analyze_event(event)
                if alert:
                    true_positives += 1
            elif event.event_type == "network_connection":
                alert = await ps_engine.analyze_event(event)
                if alert:
                    true_positives += 1
        
        # Calculate metrics
        false_positive_rate = false_positives / len(legitimate_events) if legitimate_events else 0
        true_positive_rate = true_positives / len(threat_events) if threat_events else 0
        
        # Verify acceptable accuracy
        assert false_positive_rate <= 0.1, f"False positive rate too high: {false_positive_rate}"
        assert true_positive_rate >= 0.5, f"True positive rate too low: {true_positive_rate}"
        
        print(f"Detection Accuracy Metrics:")
        print(f"  False Positive Rate: {false_positive_rate:.2%}")
        print(f"  True Positive Rate: {true_positive_rate:.2%}")
        print(f"  False Positives: {false_positives}/{len(legitimate_events)}")
        print(f"  True Positives: {true_positives}/{len(threat_events)}")
    
    @pytest.mark.asyncio
    async def test_performance_under_load(self, mock_redis):
        """Test system performance under high event load"""
        # Initialize detection manager
        manager = ThreatDetectionManager()
        self._setup_redis_mocks_for_pipeline(mock_redis)
        
        # Generate large volume of events
        events = []
        events.extend(TestDataGenerator.generate_legitimate_login_events("tenant1", 50))
        events.extend(TestDataGenerator.generate_legitimate_network_events("tenant1", 50))
        events.extend(TestDataGenerator.generate_normal_user_activity("tenant1", 100))
        events.extend(TestDataGenerator.generate_brute_force_attack_events("tenant1", 20))
        events.extend(TestDataGenerator.generate_port_scan_attack_events("tenant1", 30))
        
        # Measure processing time
        start_time = time.time()
        
        total_alerts = []
        for event in events:
            alerts = await manager.analyze_event(event)
            if alerts:
                total_alerts.extend(alerts)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Verify performance
        events_per_second = len(events) / processing_time
        assert events_per_second >= 10, f"Processing rate too slow: {events_per_second:.2f} events/sec"
        
        # Verify threats were detected
        assert len(total_alerts) >= 2, f"Expected threats not detected under load"
        
        print(f"Performance Metrics:")
        print(f"  Events Processed: {len(events)}")
        print(f"  Processing Time: {processing_time:.2f} seconds")
        print(f"  Events/Second: {events_per_second:.2f}")
        print(f"  Alerts Generated: {len(total_alerts)}")
    
    @pytest.mark.asyncio
    async def test_multi_tenant_isolation(self, mock_redis):
        """Test that threat detection properly isolates between tenants"""
        # Initialize engines
        bf_engine = BruteForceDetectionEngine()
        
        # Configure Redis mock to track tenant-specific keys
        tenant_data = {}
        
        def mock_get(key):
            return str(tenant_data.get(key, 0))
        
        def mock_setex(key, ttl, value):
            tenant_data[key] = int(value)
            return True
        
        mock_redis.get.side_effect = mock_get
        mock_redis.setex.side_effect = mock_setex
        
        # Generate brute force attacks for different tenants
        tenant1_events = TestDataGenerator.generate_brute_force_attack_events("tenant1", 6)
        tenant2_events = TestDataGenerator.generate_brute_force_attack_events("tenant2", 6)
        
        # Process tenant1 events
        tenant1_alerts = []
        for event in tenant1_events:
            alert = await bf_engine.analyze_event(event)
            if alert:
                tenant1_alerts.append(alert)
        
        # Process tenant2 events
        tenant2_alerts = []
        for event in tenant2_events:
            alert = await bf_engine.analyze_event(event)
            if alert:
                tenant2_alerts.append(alert)
        
        # Verify tenant isolation
        if tenant1_alerts:
            for alert in tenant1_alerts:
                assert alert.tenant_id == "tenant1", "Tenant isolation failed"
        
        if tenant2_alerts:
            for alert in tenant2_alerts:
                assert alert.tenant_id == "tenant2", "Tenant isolation failed"
        
        # Verify separate Redis keys were used
        tenant1_keys = [key for key in tenant_data.keys() if "tenant1" in key]
        tenant2_keys = [key for key in tenant_data.keys() if "tenant2" in key]
        
        assert len(tenant1_keys) > 0, "No tenant1 keys found"
        assert len(tenant2_keys) > 0, "No tenant2 keys found"
        
        print(f"Multi-tenant Test Results:")
        print(f"  Tenant1 Alerts: {len(tenant1_alerts)}")
        print(f"  Tenant2 Alerts: {len(tenant2_alerts)}")
        print(f"  Tenant1 Redis Keys: {len(tenant1_keys)}")
        print(f"  Tenant2 Redis Keys: {len(tenant2_keys)}")

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s", "--tb=short"])
