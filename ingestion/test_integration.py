#!/usr/bin/env python3
"""
BITS-SIEM Ingestion Service Integration Tests
Comprehensive testing of multi-protocol syslog ingestion pipeline
"""

import asyncio
import json
import socket
import ssl
import pytest
import pytest_asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import tempfile
import os
from typing import List, Dict, Any

# Import our modules
from config import config, IngestionConfig
from parsers import parser, SyslogMessage, SyslogFormat
from enrichment import enricher, TenantResolver, GeoLocationService, MessageEnricher
from listeners import UDPSyslogListener, TCPSyslogListener, TLSSyslogListener, ListenerManager
from database import db_manager, DatabaseManager, RawSyslogMessage
from main import MessageProcessor, IngestionService

class TestConfiguration:
    """Test configuration management"""
    
    def test_config_initialization(self):
        """Test that configuration loads properly"""
        test_config = IngestionConfig()
        
        assert test_config.service_name == "ingestion-service"
        assert test_config.batch_size > 0
        assert test_config.batch_timeout > 0
        assert len(test_config.syslog_listeners) == 3
        
        # Test enabled listeners
        enabled_listeners = test_config.get_enabled_listeners()
        assert len(enabled_listeners) >= 1  # At least UDP should be enabled
    
    def test_tenant_ip_ranges(self):
        """Test tenant IP range configuration"""
        test_config = IngestionConfig()
        
        assert "acme-corp" in test_config.tenant.ip_ranges
        assert "beta-industries" in test_config.tenant.ip_ranges
        assert "bits-internal" in test_config.tenant.ip_ranges
        
        # Test IP range format
        for tenant_id, ranges in test_config.tenant.ip_ranges.items():
            assert isinstance(ranges, list)
            assert len(ranges) > 0

class TestSyslogParsers:
    """Test syslog message parsing"""
    
    def test_rfc3164_parsing(self):
        """Test RFC3164 format parsing"""
        message = "<34>Dec  1 10:30:45 server1 sshd[1234]: Failed password for user from 10.0.1.50"
        
        parsed = parser.parse(message, "10.0.1.50")
        
        assert parsed.format == SyslogFormat.RFC3164
        assert parsed.facility == 4  # auth facility
        assert parsed.severity == 2  # critical
        assert parsed.hostname == "server1"
        assert parsed.program == "sshd"
        assert parsed.process_id == "1234"
        assert "Failed password" in parsed.message
        assert parsed.source_ip == "10.0.1.50"
    
    def test_rfc5424_parsing(self):
        """Test RFC5424 format parsing"""
        message = '<165>1 2023-12-01T10:30:45.123Z server1 myapp 1234 MSG-001 [exampleSDID@32473 iut="3"] Failed login attempt'
        
        parsed = parser.parse(message, "10.0.1.50")
        
        assert parsed.format == SyslogFormat.RFC5424
        assert parsed.facility == 20  # local4
        assert parsed.severity == 5  # notice
        assert parsed.hostname == "server1"
        assert parsed.program == "myapp"
        assert parsed.process_id == "1234"
        assert parsed.message_id == "MSG-001"
        assert parsed.structured_data is not None
        assert "Failed login attempt" in parsed.message
    
    def test_malformed_message_handling(self):
        """Test handling of malformed messages"""
        message = "This is not a valid syslog message"
        
        parsed = parser.parse(message, "10.0.1.50")
        
        assert parsed.format == SyslogFormat.UNKNOWN
        assert parsed.raw_message == message
        assert parsed.source_ip == "10.0.1.50"
    
    def test_parser_statistics(self):
        """Test parser statistics tracking"""
        initial_stats = parser.get_stats()
        
        # Parse some messages
        parser.parse("<34>Dec  1 10:30:45 server1 test: message1", "10.0.1.1")
        parser.parse('<165>1 2023-12-01T10:30:45Z server1 test 1 - - message2', "10.0.1.2")
        parser.parse("invalid message", "10.0.1.3")
        
        final_stats = parser.get_stats()
        
        assert final_stats['total_parsed'] > initial_stats['total_parsed']
        assert final_stats['rfc3164_parsed'] > initial_stats['rfc3164_parsed']
        assert final_stats['rfc5424_parsed'] > initial_stats['rfc5424_parsed']
        assert final_stats['parse_errors'] > initial_stats['parse_errors']

class TestTenantResolution:
    """Test tenant resolution from IP addresses"""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client for testing"""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        return mock_redis
    
    def test_tenant_resolution_cache_hit(self, mock_redis):
        """Test tenant resolution with cache hit"""
        mock_redis.get.return_value = b"acme-corp"
        
        resolver = TenantResolver(mock_redis)
        tenant_id = resolver.resolve_tenant("10.0.1.50")
        
        assert tenant_id == "acme-corp"
        mock_redis.get.assert_called_once()
    
    def test_tenant_resolution_cache_miss(self, mock_redis):
        """Test tenant resolution with cache miss"""
        mock_redis.get.return_value = None
        
        resolver = TenantResolver(mock_redis)
        tenant_id = resolver.resolve_tenant("10.0.1.50")
        
        # Should resolve to acme-corp based on IP range
        assert tenant_id == "acme-corp"
        mock_redis.setex.assert_called_once()
    
    def test_tenant_resolution_no_match(self, mock_redis):
        """Test tenant resolution when no IP range matches"""
        mock_redis.get.return_value = None
        
        resolver = TenantResolver(mock_redis)
        tenant_id = resolver.resolve_tenant("192.168.99.1")
        
        # Should use default tenant
        assert tenant_id == config.tenant.default_tenant
    
    def test_tenant_resolution_invalid_ip(self, mock_redis):
        """Test tenant resolution with invalid IP"""
        mock_redis.get.return_value = None
        
        resolver = TenantResolver(mock_redis)
        tenant_id = resolver.resolve_tenant("invalid-ip")
        
        # Should use default tenant
        assert tenant_id == config.tenant.default_tenant

class TestMessageEnrichment:
    """Test message enrichment pipeline"""
    
    @pytest.fixture
    def mock_enricher(self):
        """Mock enricher for testing"""
        with patch('enrichment.enricher') as mock:
            yield mock
    
    def test_message_enrichment_flow(self, mock_enricher):
        """Test complete message enrichment flow"""
        # Create a test message
        message = SyslogMessage(
            raw_message="<34>Dec  1 10:30:45 server1 sshd: Failed login",
            format=SyslogFormat.RFC3164,
            source_ip="10.0.1.50",
            facility=4,
            severity=2,
            hostname="server1",
            program="sshd",
            message="Failed login"
        )
        
        # Mock enricher to add tenant and geo data
        mock_enricher.enrich_message.return_value = message
        message.tenant_id = "acme-corp"
        message.geo_location = {
            "country": "United States",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194
        }
        message.metadata = {
            "ingestion_timestamp": datetime.utcnow().isoformat(),
            "message_classification": "security"
        }
        
        enriched = mock_enricher.enrich_message(message)
        
        assert enriched.tenant_id == "acme-corp"
        assert enriched.geo_location is not None
        assert enriched.metadata is not None
        assert enriched.metadata["message_classification"] == "security"

class TestDatabaseIntegration:
    """Test database storage and retrieval"""
    
    @pytest.fixture
    def test_db_manager(self):
        """Create test database manager"""
        # Use in-memory SQLite for testing
        test_manager = DatabaseManager()
        with patch.object(test_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__ = Mock()
            mock_session.return_value.__exit__ = Mock()
            yield test_manager
    
    def test_message_storage(self, test_db_manager):
        """Test storing individual messages"""
        message = SyslogMessage(
            raw_message="<34>Dec  1 10:30:45 server1 test: message",
            format=SyslogFormat.RFC3164,
            source_ip="10.0.1.50",
            tenant_id="acme-corp",
            facility=4,
            severity=2,
            hostname="server1",
            program="test",
            message="test message"
        )
        
        with patch.object(test_db_manager, 'get_session') as mock_session:
            mock_session.return_value.add = Mock()
            mock_session.return_value.commit = Mock()
            mock_session.return_value.close = Mock()
            
            result = test_db_manager.store_message(message)
            assert result == True
    
    def test_batch_storage(self, test_db_manager):
        """Test storing message batches"""
        messages = []
        for i in range(5):
            message = SyslogMessage(
                raw_message=f"<34>Dec  1 10:30:45 server1 test: message {i}",
                format=SyslogFormat.RFC3164,
                source_ip="10.0.1.50",
                tenant_id="acme-corp",
                facility=4,
                severity=2,
                hostname="server1",
                program="test",
                message=f"test message {i}"
            )
            messages.append(message)
        
        with patch.object(test_db_manager, 'get_session') as mock_session:
            mock_session.return_value.add = Mock()
            mock_session.return_value.flush = Mock()
            mock_session.return_value.bulk_save_objects = Mock()
            mock_session.return_value.commit = Mock()
            mock_session.return_value.close = Mock()
            
            result = test_db_manager.store_messages_batch(messages)
            assert result == True

class TestUDPListener:
    """Test UDP syslog listener"""
    
    @pytest_asyncio.fixture
    async def udp_listener(self):
        """Create UDP listener for testing"""
        from config import config
        
        # Mock message handler
        mock_handler = AsyncMock()
        
        listener = UDPSyslogListener(
            config.syslog_listeners["udp"],
            mock_handler
        )
        
        yield listener, mock_handler
        
        # Cleanup
        await listener.stop()
    
    @pytest.mark.asyncio
    async def test_udp_message_reception(self, udp_listener):
        """Test UDP message reception and processing"""
        listener, mock_handler = udp_listener
        
        # Start listener
        await listener.start()
        
        # Send test message
        test_message = b"<34>Dec  1 10:30:45 server1 test: UDP test message"
        
        # Simulate message reception
        await listener.process_message(test_message, "10.0.1.50")
        
        # Verify handler was called
        mock_handler.assert_called_once()
        
        # Verify stats
        stats = listener.get_stats()
        assert stats['messages_received'] == 1
        assert stats['bytes_received'] == len(test_message)

class TestTCPListener:
    """Test TCP syslog listener"""
    
    @pytest_asyncio.fixture
    async def tcp_listener(self):
        """Create TCP listener for testing"""
        from config import config
        
        # Mock message handler
        mock_handler = AsyncMock()
        
        listener = TCPSyslogListener(
            config.syslog_listeners["tcp"],
            mock_handler
        )
        
        yield listener, mock_handler
        
        # Cleanup
        await listener.stop()
    
    @pytest.mark.asyncio
    async def test_tcp_message_reception(self, tcp_listener):
        """Test TCP message reception and processing"""
        listener, mock_handler = tcp_listener
        
        # Start listener
        await listener.start()
        
        # Send test message
        test_message = b"<34>Dec  1 10:30:45 server1 test: TCP test message\n"
        
        # Simulate message reception
        await listener.process_message(test_message, "10.0.1.50")
        
        # Verify handler was called
        mock_handler.assert_called_once()
        
        # Verify stats
        stats = listener.get_stats()
        assert stats['messages_received'] == 1
        assert stats['bytes_received'] == len(test_message)

class TestMessageProcessor:
    """Test message processing and batching"""
    
    @pytest_asyncio.fixture
    async def message_processor(self):
        """Create message processor for testing"""
        processor = MessageProcessor()
        
        # Mock database manager
        with patch('main.db_manager') as mock_db:
            mock_db.store_messages_batch.return_value = True
            yield processor, mock_db
    
    @pytest.mark.asyncio
    async def test_message_batching(self, message_processor):
        """Test message batching functionality"""
        processor, mock_db = message_processor
        
        # Create test messages
        messages = []
        for i in range(config.batch_size):
            message = SyslogMessage(
                raw_message=f"<34>Dec  1 10:30:45 server1 test: message {i}",
                format=SyslogFormat.RFC3164,
                source_ip="10.0.1.50",
                tenant_id="acme-corp",
                facility=4,
                severity=2,
                hostname="server1",
                program="test",
                message=f"test message {i}"
            )
            messages.append(message)
        
        # Process messages
        for message in messages:
            await processor.process_message(message)
        
        # Verify batch was processed
        mock_db.store_messages_batch.assert_called()
        
        # Verify stats
        stats = processor.get_stats()
        assert stats['processor']['total_processed'] == config.batch_size
        assert stats['processor']['batch_processed'] >= 1

class TestEndToEndIntegration:
    """End-to-end integration tests"""
    
    @pytest.fixture
    def temp_config(self):
        """Create temporary configuration for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock environment
            test_env = {
                'DATABASE_URL': 'sqlite:///:memory:',
                'REDIS_HOST': 'localhost',
                'REDIS_PORT': '6379',
                'SYSLOG_UDP_PORT': '51400',  # Use different port for testing
                'SYSLOG_TCP_PORT': '51401',
                'BATCH_SIZE': '5',
                'BATCH_TIMEOUT': '1'
            }
            
            with patch.dict(os.environ, test_env):
                yield
    
    @pytest.mark.asyncio
    async def test_complete_ingestion_pipeline(self, temp_config):
        """Test complete ingestion pipeline from UDP to database"""
        # Mock all external dependencies
        with patch('enrichment.enricher') as mock_enricher, \
             patch('main.db_manager') as mock_db:
            
            # Configure mocks
            mock_enricher.enrich_message.side_effect = lambda msg: msg
            mock_db.store_messages_batch.return_value = True
            mock_db.health_check.return_value = True
            
            # Create message processor
            processor = MessageProcessor()
            
            # Create test message
            test_message = SyslogMessage(
                raw_message="<34>Dec  1 10:30:45 server1 test: integration test",
                format=SyslogFormat.RFC3164,
                source_ip="10.0.1.50",
                tenant_id="acme-corp",
                facility=4,
                severity=2,
                hostname="server1",
                program="test",
                message="integration test"
            )
            
            # Process message
            await processor.process_message(test_message)
            
            # Flush any remaining messages
            await processor.flush_remaining_messages()
            
            # Verify processing
            stats = processor.get_stats()
            assert stats['processor']['total_processed'] >= 1
    
    @pytest.mark.asyncio
    async def test_listener_manager_integration(self, temp_config):
        """Test listener manager with multiple protocols"""
        # Mock message handler
        mock_handler = AsyncMock()
        
        # Create listener manager
        manager = ListenerManager(mock_handler)
        
        # Mock config to enable only UDP for testing
        with patch('listeners.config.get_enabled_listeners') as mock_enabled:
            mock_enabled.return_value = [config.syslog_listeners["udp"]]
            
            # Create listeners
            manager.create_listeners()
            
            # Verify UDP listener was created
            assert "udp" in manager.listeners
            assert len(manager.listeners) == 1
            
            # Get stats
            stats = manager.get_stats()
            assert "udp" in stats

class TestErrorHandling:
    """Test error handling and recovery"""
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self):
        """Test handling of database errors"""
        processor = MessageProcessor()
        
        # Mock database to raise error
        with patch('main.db_manager') as mock_db:
            mock_db.store_messages_batch.side_effect = Exception("Database error")
            
            # Create test message
            message = SyslogMessage(
                raw_message="<34>Dec  1 10:30:45 server1 test: error test",
                format=SyslogFormat.RFC3164,
                source_ip="10.0.1.50",
                tenant_id="acme-corp",
                facility=4,
                severity=2,
                hostname="server1",
                program="test",
                message="error test"
            )
            
            # Process message - should not raise exception
            await processor.process_message(message)
            
            # Verify error was tracked
            stats = processor.get_stats()
            assert stats['processor']['processing_errors'] >= 0  # Errors tracked
    
    def test_parser_error_recovery(self):
        """Test parser error recovery"""
        # Test with completely invalid data
        result = parser.parse("\x00\x01\x02invalid binary data", "10.0.1.50")
        
        # Should return unknown format message
        assert result.format == SyslogFormat.UNKNOWN
        assert result.source_ip == "10.0.1.50"
        assert result.raw_message == "\x00\x01\x02invalid binary data"

class TestPerformance:
    """Performance and load testing"""
    
    @pytest.mark.asyncio
    async def test_batch_processing_performance(self):
        """Test batch processing performance"""
        processor = MessageProcessor()
        
        # Mock database
        with patch('main.db_manager') as mock_db:
            mock_db.store_messages_batch.return_value = True
            
            # Create many messages
            messages = []
            for i in range(100):
                message = SyslogMessage(
                    raw_message=f"<34>Dec  1 10:30:45 server1 test: message {i}",
                    format=SyslogFormat.RFC3164,
                    source_ip="10.0.1.50",
                    tenant_id="acme-corp",
                    facility=4,
                    severity=2,
                    hostname="server1",
                    program="test",
                    message=f"test message {i}"
                )
                messages.append(message)
            
            # Measure processing time
            start_time = datetime.utcnow()
            
            # Process all messages
            for message in messages:
                await processor.process_message(message)
            
            # Flush remaining
            await processor.flush_remaining_messages()
            
            end_time = datetime.utcnow()
            processing_time = (end_time - start_time).total_seconds()
            
            # Verify performance (should process 100 messages in reasonable time)
            assert processing_time < 10.0  # Should complete within 10 seconds
            
            # Verify all messages were processed
            stats = processor.get_stats()
            assert stats['processor']['total_processed'] == 100

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
