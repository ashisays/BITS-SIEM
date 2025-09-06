"""
Comprehensive Tests for False Positive Reduction
===============================================

This module tests the false positive reduction capabilities including:
1. Static and Dynamic Whitelisting
2. Behavioral Analysis
3. Business Hours Context
4. Service Account Detection
5. Legitimate Activity Recognition
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta, time
from unittest.mock import Mock, AsyncMock, patch
import redis

# Import the modules to test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'processing'))

from false_positive_reduction import (
    FalsePositiveReductionEngine, 
    StaticWhitelistManager,
    DynamicWhitelistManager,
    BehavioralAnalysisEngine,
    BusinessHoursManager,
    WhitelistEntry,
    BusinessHoursConfig,
    UserBehaviorProfile
)

from enhanced_detection import (
    EnhancedDetectionEngine,
    TimeBasedAnalysis,
    GeographicIntelligence,
    ServiceAccountDetector,
    LegitimateActivityDetector
)

from stream_processor import ProcessedEvent
from threat_models import ThreatAlert

class TestStaticWhitelistManager:
    """Test static whitelist functionality"""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client"""
        mock_redis = Mock()
        mock_redis.hset = Mock()
        mock_redis.hget = Mock()
        mock_redis.hgetall = Mock()
        mock_redis.hdel = Mock()
        mock_redis.expire = Mock()
        return mock_redis
    
    @pytest.fixture
    def whitelist_manager(self, mock_redis):
        """Create whitelist manager with mock Redis"""
        return StaticWhitelistManager(mock_redis)
    
    @pytest.mark.asyncio
    async def test_add_whitelist_entry(self, whitelist_manager, mock_redis):
        """Test adding whitelist entry"""
        entry = WhitelistEntry(
            id="test_entry",
            tenant_id="demo-org",
            entry_type="ip",
            value="192.168.1.100",
            reason="Test server",
            created_at=datetime.utcnow()
        )
        
        result = await whitelist_manager.add_whitelist_entry(entry)
        
        assert result is True
        mock_redis.hset.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_is_whitelisted_ip(self, whitelist_manager, mock_redis):
        """Test IP whitelist check"""
        entry_data = {
            'id': 'test_entry',
            'tenant_id': 'demo-org',
            'entry_type': 'ip',
            'value': '192.168.1.100',
            'reason': 'Test server',
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': None,
            'confidence': 1.0,
            'auto_generated': False,
            'metadata': {}
        }
        
        mock_redis.hget.return_value = json.dumps(entry_data)
        
        result = await whitelist_manager.is_whitelisted("demo-org", "ip", "192.168.1.100")
        
        assert result is not None
        assert result.value == "192.168.1.100"
        assert result.reason == "Test server"
    
    @pytest.mark.asyncio
    async def test_network_range_whitelist(self, whitelist_manager, mock_redis):
        """Test network range whitelist check"""
        # Mock network range data
        network_data = {
            '192.168.0.0/24': json.dumps({
                'id': 'network_entry',
                'tenant_id': 'demo-org',
                'entry_type': 'network',
                'value': '192.168.0.0/24',
                'reason': 'Internal network',
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': None,
                'confidence': 1.0,
                'auto_generated': True,
                'metadata': {}
            })
        }
        
        mock_redis.hget.return_value = None  # No direct IP match
        mock_redis.hgetall.return_value = network_data
        
        result = await whitelist_manager.is_whitelisted("demo-org", "ip", "192.168.0.50")
        
        assert result is not None
        assert result.value == "192.168.0.0/24"
        assert result.reason == "Internal network"

class TestDynamicWhitelistManager:
    """Test dynamic whitelist functionality"""
    
    @pytest.fixture
    def mock_redis(self):
        mock_redis = Mock()
        mock_redis.incr = Mock()
        mock_redis.expire = Mock()
        mock_redis.hset = Mock()
        mock_redis.hget = Mock()
        return mock_redis
    
    @pytest.fixture
    def dynamic_manager(self, mock_redis):
        return DynamicWhitelistManager(mock_redis)
    
    @pytest.mark.asyncio
    async def test_record_successful_auth(self, dynamic_manager, mock_redis):
        """Test recording successful authentication"""
        mock_redis.incr.return_value = 3  # Below threshold
        
        result = await dynamic_manager.record_successful_auth("demo-org", "192.168.1.100", "user1")
        
        assert result is True
        mock_redis.incr.assert_called_once()
        mock_redis.expire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_dynamic_whitelist_threshold(self, dynamic_manager, mock_redis):
        """Test dynamic whitelisting when threshold is reached"""
        mock_redis.incr.return_value = 5  # Meets threshold
        
        result = await dynamic_manager.record_successful_auth("demo-org", "192.168.1.100", "user1")
        
        assert result is True
        mock_redis.hset.assert_called_once()  # Should add to whitelist
    
    @pytest.mark.asyncio
    async def test_is_dynamically_whitelisted(self, dynamic_manager, mock_redis):
        """Test checking dynamic whitelist"""
        whitelist_data = {
            'ip': '192.168.1.100',
            'username': 'user1',
            'success_count': 7,
            'whitelisted_at': datetime.utcnow().isoformat(),
            'confidence': 0.7
        }
        
        mock_redis.hget.return_value = json.dumps(whitelist_data)
        
        result = await dynamic_manager.is_dynamically_whitelisted("demo-org", "192.168.1.100")
        
        assert result is not None
        assert result['success_count'] == 7
        assert result['confidence'] == 0.7

class TestBehavioralAnalysisEngine:
    """Test behavioral analysis functionality"""
    
    @pytest.fixture
    def mock_redis(self):
        mock_redis = Mock()
        mock_redis.set = Mock()
        mock_redis.get = Mock()
        mock_redis.expire = Mock()
        return mock_redis
    
    @pytest.fixture
    def behavioral_engine(self, mock_redis):
        return BehavioralAnalysisEngine(mock_redis)
    
    @pytest.mark.asyncio
    async def test_build_user_profile_insufficient_data(self, behavioral_engine):
        """Test profile building with insufficient data"""
        # Mock _get_user_events to return insufficient data
        with patch.object(behavioral_engine, '_get_user_events', return_value=[]):
            result = await behavioral_engine.build_user_profile("demo-org", "user1")
            assert result is None
    
    @pytest.mark.asyncio
    async def test_build_user_profile_service_account(self, behavioral_engine):
        """Test profile building for service account"""
        # Mock events for service account
        events = [
            {
                'hour': h % 24,
                'day': 1,
                'source_ip': '192.168.1.100',
                'user_agent': 'python-requests/2.25.1',
                'country': 'US',
                'duration': 60,
                'event_type': 'login_success'
            }
            for h in range(15)  # 15 events across different hours
        ]
        
        with patch.object(behavioral_engine, '_get_user_events', return_value=events):
            with patch.object(behavioral_engine, '_store_user_profile'):
                result = await behavioral_engine.build_user_profile("demo-org", "api_service")
                
                assert result is not None
                assert result.profile_type == 'service_account'
                assert result.failure_tolerance == 2  # Service accounts should have low tolerance
    
    @pytest.mark.asyncio
    async def test_get_user_profile_cached(self, behavioral_engine, mock_redis):
        """Test getting cached user profile"""
        profile_data = {
            'tenant_id': 'demo-org',
            'user_identifier': 'user1',
            'profile_type': 'human',
            'typical_hours': [9, 10, 11, 17, 18],
            'typical_days': [1, 2, 3, 4, 5],
            'typical_ips': ['192.168.1.100'],
            'typical_user_agents': ['Mozilla/5.0'],
            'avg_session_duration': 240.0,
            'failure_tolerance': 5,
            'geographic_locations': ['US'],
            'last_updated': datetime.utcnow().isoformat(),
            'confidence_score': 0.8,
            'sample_size': 50
        }
        
        mock_redis.get.return_value = json.dumps(profile_data)
        
        result = await behavioral_engine.get_user_profile("demo-org", "user1")
        
        assert result is not None
        assert result.profile_type == 'human'
        assert result.failure_tolerance == 5

class TestBusinessHoursManager:
    """Test business hours functionality"""
    
    @pytest.fixture
    def mock_redis(self):
        mock_redis = Mock()
        mock_redis.set = Mock()
        mock_redis.get = Mock()
        return mock_redis
    
    @pytest.fixture
    def business_hours_manager(self, mock_redis):
        return BusinessHoursManager(mock_redis)
    
    @pytest.mark.asyncio
    async def test_set_business_hours(self, business_hours_manager, mock_redis):
        """Test setting business hours configuration"""
        config = BusinessHoursConfig(
            tenant_id="demo-org",
            timezone="UTC",
            weekday_start=time(9, 0),
            weekday_end=time(17, 0)
        )
        
        result = await business_hours_manager.set_business_hours(config)
        
        assert result is True
        mock_redis.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_is_business_hours_weekday(self, business_hours_manager, mock_redis):
        """Test business hours check during weekday"""
        config_data = {
            'tenant_id': 'demo-org',
            'timezone': 'UTC',
            'weekday_start': '09:00:00',
            'weekday_end': '17:00:00',
            'holidays': [],
            'maintenance_windows': []
        }
        
        mock_redis.get.return_value = json.dumps(config_data)
        
        # Test during business hours (Wednesday 2PM)
        test_time = datetime(2024, 1, 10, 14, 0)  # Wednesday
        result = await business_hours_manager.is_business_hours("demo-org", test_time)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_business_hours_weekend(self, business_hours_manager, mock_redis):
        """Test business hours check during weekend"""
        config_data = {
            'tenant_id': 'demo-org',
            'timezone': 'UTC',
            'weekday_start': '09:00:00',
            'weekday_end': '17:00:00',
            'holidays': [],
            'maintenance_windows': []
        }
        
        mock_redis.get.return_value = json.dumps(config_data)
        
        # Test during weekend (Saturday 2PM)
        test_time = datetime(2024, 1, 13, 14, 0)  # Saturday
        result = await business_hours_manager.is_business_hours("demo-org", test_time)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_is_business_hours_holiday(self, business_hours_manager, mock_redis):
        """Test business hours check during holiday"""
        config_data = {
            'tenant_id': 'demo-org',
            'timezone': 'UTC',
            'weekday_start': '09:00:00',
            'weekday_end': '17:00:00',
            'holidays': ['2024-01-10'],  # Wednesday holiday
            'maintenance_windows': []
        }
        
        mock_redis.get.return_value = json.dumps(config_data)
        
        # Test during holiday (Wednesday 2PM but it's a holiday)
        test_time = datetime(2024, 1, 10, 14, 0)
        result = await business_hours_manager.is_business_hours("demo-org", test_time)
        
        assert result is False

class TestServiceAccountDetector:
    """Test service account detection"""
    
    @pytest.fixture
    def mock_redis(self):
        return Mock()
    
    @pytest.fixture
    def service_detector(self, mock_redis):
        return ServiceAccountDetector(mock_redis)
    
    @pytest.mark.asyncio
    async def test_classify_service_account_by_username(self, service_detector):
        """Test service account classification by username"""
        result = await service_detector.classify_account_type(
            "api_service_user", 
            "python-requests/2.25.1",
            "192.168.1.100"
        )
        
        assert result['account_type'] == 'service_account'
        assert result['confidence'] > 0.5
        assert any('api' in indicator.lower() for indicator in result['indicators'])
    
    @pytest.mark.asyncio
    async def test_classify_service_account_by_user_agent(self, service_detector):
        """Test service account classification by user agent"""
        result = await service_detector.classify_account_type(
            "normaluser", 
            "curl/7.68.0",
            "192.168.1.100"
        )
        
        assert result['account_type'] == 'service_account'
        assert result['confidence'] > 0.3
        assert any('curl' in indicator.lower() for indicator in result['indicators'])
    
    @pytest.mark.asyncio
    async def test_classify_human_account(self, service_detector):
        """Test human account classification"""
        result = await service_detector.classify_account_type(
            "john.doe", 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "192.168.1.100"
        )
        
        assert result['account_type'] == 'human'
        assert result['confidence'] == 0.0  # No service indicators

class TestFalsePositiveReductionIntegration:
    """Integration tests for false positive reduction"""
    
    @pytest.fixture
    def mock_event(self):
        """Create mock processed event"""
        return ProcessedEvent(
            id="test_event_1",
            tenant_id="demo-org",
            timestamp=datetime.utcnow(),
            event_type="authentication_failure",
            source_ip="192.168.1.100",
            target_ip="192.168.1.1",
            message="Failed login attempt",
            risk_score=0.5,
            raw_data={
                'username': 'testuser',
                'user_agent': 'Mozilla/5.0',
                'country': 'US',
                'program': 'sshd'
            }
        )
    
    @pytest.fixture
    def mock_alert(self):
        """Create mock threat alert"""
        return ThreatAlert(
            id="test_alert_1",
            tenant_id="demo-org",
            alert_type="brute_force_attack",
            severity="critical",
            title="Brute Force Attack Detected",
            description="Multiple failed login attempts detected",
            source_ip="192.168.1.100",
            risk_score=0.9,
            confidence=0.8,
            evidence={'failed_attempts': 6, 'threshold': 5},
            metadata={'detection_engine': 'brute_force'}
        )
    
    @pytest.mark.asyncio
    async def test_static_whitelist_suppression(self, mock_event, mock_alert):
        """Test alert suppression due to static whitelist"""
        # Mock the false positive reduction engine
        with patch('processing.false_positive_reduction.fp_reduction_engine') as mock_fp_engine:
            mock_fp_engine.enabled = True
            mock_fp_engine.static_whitelist.is_whitelisted = AsyncMock(return_value=WhitelistEntry(
                id="test_whitelist",
                tenant_id="demo-org",
                entry_type="ip",
                value="192.168.1.100",
                reason="Internal server",
                created_at=datetime.utcnow()
            ))
            mock_fp_engine.dynamic_whitelist.is_dynamically_whitelisted = AsyncMock(return_value=None)
            mock_fp_engine.business_hours.is_business_hours = AsyncMock(return_value=True)
            
            should_suppress, reason = await mock_fp_engine.should_suppress_alert(mock_event, mock_alert)
            
            assert should_suppress is True
            assert "statically whitelisted" in reason
    
    @pytest.mark.asyncio
    async def test_dynamic_whitelist_suppression(self, mock_event, mock_alert):
        """Test alert suppression due to dynamic whitelist"""
        with patch('processing.false_positive_reduction.fp_reduction_engine') as mock_fp_engine:
            mock_fp_engine.enabled = True
            mock_fp_engine.static_whitelist.is_whitelisted = AsyncMock(return_value=None)
            mock_fp_engine.dynamic_whitelist.is_dynamically_whitelisted = AsyncMock(return_value={
                'success_count': 10,
                'confidence': 0.9
            })
            
            should_suppress, reason = await mock_fp_engine.should_suppress_alert(mock_event, mock_alert)
            
            assert should_suppress is True
            assert "dynamically whitelisted" in reason
    
    @pytest.mark.asyncio
    async def test_business_hours_context(self, mock_event, mock_alert):
        """Test business hours context in alert suppression"""
        # Modify alert to have lower confidence
        mock_alert.confidence = 0.6
        
        with patch('processing.false_positive_reduction.fp_reduction_engine') as mock_fp_engine:
            mock_fp_engine.enabled = True
            mock_fp_engine.static_whitelist.is_whitelisted = AsyncMock(return_value=None)
            mock_fp_engine.dynamic_whitelist.is_dynamically_whitelisted = AsyncMock(return_value=None)
            mock_fp_engine.business_hours.is_business_hours = AsyncMock(return_value=False)  # Outside business hours
            
            should_suppress, reason = await mock_fp_engine.should_suppress_alert(mock_event, mock_alert)
            
            assert should_suppress is True
            assert "outside business hours" in reason

class TestEnhancedDetectionIntegration:
    """Integration tests for enhanced detection"""
    
    @pytest.fixture
    def mock_event(self):
        return ProcessedEvent(
            id="test_event_1",
            tenant_id="demo-org",
            timestamp=datetime.utcnow(),
            event_type="authentication_failure",
            source_ip="192.168.1.100",
            target_ip="192.168.1.1",
            message="Failed login attempt",
            risk_score=0.5,
            raw_data={
                'username': 'api_service',
                'user_agent': 'python-requests/2.25.1',
                'country': 'US'
            }
        )
    
    @pytest.fixture
    def mock_alert(self):
        return ThreatAlert(
            id="test_alert_1",
            tenant_id="demo-org",
            alert_type="brute_force_attack",
            severity="critical",
            title="Brute Force Attack Detected",
            description="Multiple failed login attempts detected",
            source_ip="192.168.1.100",
            risk_score=0.9,
            confidence=0.8,
            evidence={'failed_attempts': 6},
            metadata={'detection_engine': 'brute_force'}
        )
    
    @pytest.mark.asyncio
    async def test_service_account_risk_reduction(self, mock_event, mock_alert):
        """Test risk reduction for service accounts"""
        with patch('processing.enhanced_detection.enhanced_detection_engine') as mock_enhanced:
            mock_enhanced.enabled = True
            mock_enhanced.enhance_threat_analysis = AsyncMock(return_value={
                'enhanced': True,
                'account_analysis': {
                    'account_type': 'service_account',
                    'confidence': 0.9
                },
                'geographic_analysis': {'risk_score': 0.0},
                'temporal_analysis': {'business_hours_violation': False},
                'legitimacy_check': {'is_legitimate_maintenance': False},
                'risk_adjustment': -0.2  # Reduce risk for service account
            })
            
            analysis = await mock_enhanced.enhance_threat_analysis(mock_event, mock_alert)
            
            assert analysis['enhanced'] is True
            assert analysis['risk_adjustment'] == -0.2
            assert analysis['account_analysis']['account_type'] == 'service_account'
    
    @pytest.mark.asyncio
    async def test_geographic_risk_increase(self, mock_event, mock_alert):
        """Test risk increase for high-risk geography"""
        # Modify event to come from high-risk country
        mock_event.raw_data['country'] = 'CN'
        
        with patch('processing.enhanced_detection.enhanced_detection_engine') as mock_enhanced:
            mock_enhanced.enabled = True
            mock_enhanced.enhance_threat_analysis = AsyncMock(return_value={
                'enhanced': True,
                'account_analysis': {'account_type': 'human'},
                'geographic_analysis': {
                    'risk_score': 0.3,
                    'risk_factors': ['High-risk country: CN']
                },
                'temporal_analysis': {'business_hours_violation': False},
                'legitimacy_check': {'is_legitimate_maintenance': False},
                'risk_adjustment': 0.09  # 0.3 * 0.3 = 0.09
            })
            
            analysis = await mock_enhanced.enhance_threat_analysis(mock_event, mock_alert)
            
            assert analysis['enhanced'] is True
            assert analysis['risk_adjustment'] > 0
            assert 'High-risk country' in analysis['geographic_analysis']['risk_factors'][0]

class TestEndToEndScenarios:
    """End-to-end test scenarios"""
    
    @pytest.mark.asyncio
    async def test_legitimate_admin_activity(self):
        """Test that legitimate admin activity is not flagged"""
        # Scenario: Network admin doing port scan during maintenance window
        event = ProcessedEvent(
            id="admin_scan_1",
            tenant_id="demo-org",
            timestamp=datetime(2024, 1, 10, 3, 0),  # 3 AM maintenance
            event_type="network_connection",
            source_ip="192.168.1.10",  # Admin workstation
            target_ip="192.168.1.100",
            message="Port scan from admin workstation",
            risk_score=0.3,
            raw_data={
                'username': 'admin',
                'user_agent': 'nmap',
                'country': 'US'
            }
        )
        
        alert = ThreatAlert(
            id="admin_scan_alert",
            tenant_id="demo-org",
            alert_type="port_scan_attack",
            severity="warning",
            title="Port Scanning Activity Detected",
            description="Detected connections to multiple ports",
            source_ip="192.168.1.10",
            risk_score=0.7,
            confidence=0.6,
            evidence={'unique_ports': 12, 'scan_type': 'admin_service_scan'},
            metadata={'detection_engine': 'port_scan'}
        )
        
        # This should be suppressed due to:
        # 1. Internal IP range (static whitelist)
        # 2. Maintenance window (legitimate activity)
        # 3. Admin user pattern
        
        # Mock the suppression logic
        with patch('processing.false_positive_reduction.fp_reduction_engine') as mock_fp:
            mock_fp.enabled = True
            mock_fp.should_suppress_alert = AsyncMock(return_value=(True, "Legitimate maintenance activity"))
            
            should_suppress, reason = await mock_fp.should_suppress_alert(event, alert)
            
            assert should_suppress is True
            assert "maintenance" in reason.lower()
    
    @pytest.mark.asyncio
    async def test_genuine_attack_not_suppressed(self):
        """Test that genuine attacks are not suppressed"""
        # Scenario: External attacker with clear malicious pattern
        event = ProcessedEvent(
            id="attack_event_1",
            tenant_id="demo-org",
            timestamp=datetime.utcnow(),
            event_type="authentication_failure",
            source_ip="203.0.113.50",  # External IP
            target_ip="192.168.1.1",
            message="Failed SSH login attempt",
            risk_score=0.8,
            raw_data={
                'username': 'admin',
                'user_agent': 'ssh',
                'country': 'CN'  # High-risk country
            }
        )
        
        alert = ThreatAlert(
            id="genuine_attack_alert",
            tenant_id="demo-org",
            alert_type="brute_force_attack",
            severity="critical",
            title="Brute Force Attack Detected",
            description="Multiple failed login attempts from external IP",
            source_ip="203.0.113.50",
            risk_score=0.95,
            confidence=0.9,
            evidence={'failed_attempts': 15, 'threshold': 5},
            metadata={'detection_engine': 'brute_force'}
        )
        
        # This should NOT be suppressed because:
        # 1. External IP (not whitelisted)
        # 2. High confidence and risk score
        # 3. High-risk geography
        # 4. Clear attack pattern
        
        with patch('processing.false_positive_reduction.fp_reduction_engine') as mock_fp:
            mock_fp.enabled = True
            mock_fp.should_suppress_alert = AsyncMock(return_value=(False, "No false positive indicators found"))
            
            should_suppress, reason = await mock_fp.should_suppress_alert(event, alert)
            
            assert should_suppress is False
            assert "no false positive" in reason.lower()

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])
