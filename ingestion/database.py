"""
BITS-SIEM Ingestion Database Integration
Storage and retrieval of ingested syslog messages
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
import json

from config import config
from parsers import SyslogMessage

logger = logging.getLogger(__name__)

# Database setup
engine = create_engine(
    config.database.url,
    pool_size=config.database.pool_size,
    max_overflow=config.database.max_overflow,
    pool_timeout=config.database.pool_timeout,
    pool_recycle=config.database.pool_recycle,
    echo=config.debug
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class RawSyslogMessage(Base):
    """Raw syslog message storage"""
    __tablename__ = "raw_syslog_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    source_ip = Column(String, nullable=False, index=True)
    raw_message = Column(Text, nullable=False)
    parsed_message = Column(JSON)
    enriched_data = Column(JSON)
    
    # Syslog fields
    timestamp = Column(DateTime, index=True)
    hostname = Column(String, index=True)
    facility = Column(Integer)
    severity = Column(Integer)
    program = Column(String, index=True)
    
    # Processing metadata
    ingestion_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    processing_status = Column(String, default='ingested')  # ingested, processed, failed
    
    # Indexing for fast queries
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SyslogMessageBatch(Base):
    """Batch processing tracking"""
    __tablename__ = "syslog_message_batches"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    batch_size = Column(Integer, nullable=False)
    processing_status = Column(String, default='pending')  # pending, processing, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    processed_at = Column(DateTime)
    error_message = Column(Text)

class DatabaseManager:
    """Database operations for ingestion service"""
    
    def __init__(self):
        self.stats = {
            'messages_stored': 0,
            'batches_created': 0,
            'database_errors': 0,
            'connection_errors': 0
        }
    
    def create_tables(self):
        """Create database tables"""
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get database session"""
        try:
            return SessionLocal()
        except SQLAlchemyError as e:
            self.stats['connection_errors'] += 1
            logger.error(f"Database connection failed: {e}")
            raise
    
    def store_message(self, message: SyslogMessage) -> bool:
        """Store a single syslog message"""
        session = self.get_session()
        try:
            # Convert message to database record
            db_message = RawSyslogMessage(
                tenant_id=message.tenant_id or 'unknown',
                source_ip=message.source_ip or 'unknown',
                raw_message=message.raw_message,
                parsed_message=self._serialize_parsed_message(message),
                enriched_data=self._serialize_enriched_data(message),
                timestamp=message.timestamp,
                hostname=message.hostname,
                facility=message.facility,
                severity=message.severity,
                program=message.program,
                processing_status='ingested'
            )
            
            session.add(db_message)
            session.commit()
            
            self.stats['messages_stored'] += 1
            return True
            
        except SQLAlchemyError as e:
            self.stats['database_errors'] += 1
            logger.error(f"Failed to store message: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def store_messages_batch(self, messages: List[SyslogMessage]) -> bool:
        """Store multiple syslog messages in a batch"""
        if not messages:
            return True
        
        session = self.get_session()
        try:
            # Create batch record
            batch = SyslogMessageBatch(
                tenant_id=messages[0].tenant_id or 'unknown',
                batch_size=len(messages),
                processing_status='processing'
            )
            session.add(batch)
            session.flush()  # Get batch ID
            
            # Convert messages to database records
            db_messages = []
            for message in messages:
                db_message = RawSyslogMessage(
                    tenant_id=message.tenant_id or 'unknown',
                    source_ip=message.source_ip or 'unknown',
                    raw_message=message.raw_message,
                    parsed_message=self._serialize_parsed_message(message),
                    enriched_data=self._serialize_enriched_data(message),
                    timestamp=message.timestamp,
                    hostname=message.hostname,
                    facility=message.facility,
                    severity=message.severity,
                    program=message.program,
                    processing_status='ingested'
                )
                db_messages.append(db_message)
            
            # Bulk insert
            session.bulk_save_objects(db_messages)
            
            # Update batch status
            batch.processing_status = 'completed'
            batch.processed_at = datetime.utcnow()
            
            session.commit()
            
            self.stats['messages_stored'] += len(messages)
            self.stats['batches_created'] += 1
            return True
            
        except SQLAlchemyError as e:
            self.stats['database_errors'] += 1
            logger.error(f"Failed to store message batch: {e}")
            session.rollback()
            
            # Update batch status to failed
            try:
                batch.processing_status = 'failed'
                batch.error_message = str(e)
                session.commit()
            except:
                pass
            
            return False
        finally:
            session.close()
    
    def get_recent_messages(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent messages for a tenant"""
        session = self.get_session()
        try:
            messages = session.query(RawSyslogMessage).filter(
                RawSyslogMessage.tenant_id == tenant_id
            ).order_by(
                RawSyslogMessage.ingestion_timestamp.desc()
            ).limit(limit).all()
            
            return [self._message_to_dict(msg) for msg in messages]
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to retrieve messages: {e}")
            return []
        finally:
            session.close()
    
    def get_message_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get message statistics"""
        session = self.get_session()
        try:
            query = session.query(RawSyslogMessage)
            
            if tenant_id:
                query = query.filter(RawSyslogMessage.tenant_id == tenant_id)
            
            total_messages = query.count()
            
            # Get messages by severity
            severity_counts = {}
            for severity in range(8):
                count = query.filter(RawSyslogMessage.severity == severity).count()
                severity_counts[severity] = count
            
            # Get recent activity (last 24 hours)
            recent_query = query.filter(
                RawSyslogMessage.ingestion_timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            )
            recent_messages = recent_query.count()
            
            return {
                'total_messages': total_messages,
                'recent_messages': recent_messages,
                'severity_counts': severity_counts,
                'tenant_id': tenant_id
            }
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to get message stats: {e}")
            return {}
        finally:
            session.close()
    
    def cleanup_old_messages(self, days_to_keep: int = 30) -> int:
        """Clean up old messages"""
        session = self.get_session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            deleted_count = session.query(RawSyslogMessage).filter(
                RawSyslogMessage.ingestion_timestamp < cutoff_date
            ).delete()
            
            session.commit()
            
            logger.info(f"Cleaned up {deleted_count} old messages")
            return deleted_count
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to cleanup old messages: {e}")
            session.rollback()
            return 0
        finally:
            session.close()
    
    def _serialize_parsed_message(self, message: SyslogMessage) -> Dict[str, Any]:
        """Convert parsed message to JSON-serializable format"""
        try:
            return {
                'format': message.format.value if message.format else None,
                'facility': message.facility,
                'severity': message.severity,
                'priority': message.priority,
                'program': message.program,
                'process_id': message.process_id,
                'message_id': message.message_id,
                'message': message.message,
                'structured_data': message.structured_data
            }
        except Exception as e:
            logger.error(f"Failed to serialize parsed message: {e}")
            return {}
    
    def _serialize_enriched_data(self, message: SyslogMessage) -> Dict[str, Any]:
        """Convert enriched data to JSON-serializable format"""
        try:
            return {
                'geo_location': message.geo_location,
                'metadata': message.metadata
            }
        except Exception as e:
            logger.error(f"Failed to serialize enriched data: {e}")
            return {}
    
    def _message_to_dict(self, message: RawSyslogMessage) -> Dict[str, Any]:
        """Convert database message to dictionary"""
        return {
            'id': message.id,
            'tenant_id': message.tenant_id,
            'source_ip': message.source_ip,
            'raw_message': message.raw_message,
            'parsed_message': message.parsed_message,
            'enriched_data': message.enriched_data,
            'timestamp': message.timestamp.isoformat() if message.timestamp else None,
            'hostname': message.hostname,
            'facility': message.facility,
            'severity': message.severity,
            'program': message.program,
            'ingestion_timestamp': message.ingestion_timestamp.isoformat(),
            'processing_status': message.processing_status
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database manager statistics"""
        return self.stats.copy()
    
    def health_check(self) -> bool:
        """Check database health"""
        try:
            session = self.get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

# Global database manager instance
db_manager = DatabaseManager()

# Initialize database tables on import
try:
    db_manager.create_tables()
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
    raise
