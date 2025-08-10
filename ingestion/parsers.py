"""
BITS-SIEM Syslog Parsers
RFC3164 and RFC5424 compliant syslog message parsing
"""

import re
import logging
from datetime import datetime
from typing import Dict, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class SyslogFormat(Enum):
    """Supported syslog formats"""
    RFC3164 = "rfc3164"
    RFC5424 = "rfc5424"
    UNKNOWN = "unknown"

@dataclass
class SyslogMessage:
    """Structured syslog message"""
    raw_message: str
    format: SyslogFormat
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    facility: Optional[int] = None
    severity: Optional[int] = None
    priority: Optional[int] = None
    program: Optional[str] = None
    process_id: Optional[str] = None
    message_id: Optional[str] = None
    message: Optional[str] = None
    structured_data: Optional[Dict[str, Any]] = None
    
    # Enrichment fields
    tenant_id: Optional[str] = None
    geo_location: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime to ISO format
        if data.get('timestamp'):
            data['timestamp'] = self.timestamp.isoformat()
        # Convert enum to string
        if data.get('format'):
            data['format'] = self.format.value
        return data

class SyslogParser:
    """Base syslog parser class"""
    
    def __init__(self):
        self.stats = {
            'total_parsed': 0,
            'rfc3164_parsed': 0,
            'rfc5424_parsed': 0,
            'parse_errors': 0
        }
    
    def parse(self, raw_message: str, source_ip: Optional[str] = None) -> SyslogMessage:
        """Parse a raw syslog message"""
        try:
            self.stats['total_parsed'] += 1
            
            # Try RFC5424 first (more structured)
            if self._is_rfc5424(raw_message):
                result = self._parse_rfc5424(raw_message, source_ip)
                self.stats['rfc5424_parsed'] += 1
                return result
            
            # Fall back to RFC3164
            result = self._parse_rfc3164(raw_message, source_ip)
            self.stats['rfc3164_parsed'] += 1
            return result
            
        except Exception as e:
            self.stats['parse_errors'] += 1
            logger.error(f"Failed to parse syslog message: {e}")
            return SyslogMessage(
                raw_message=raw_message,
                format=SyslogFormat.UNKNOWN,
                source_ip=source_ip,
                message=raw_message
            )
    
    def _is_rfc5424(self, message: str) -> bool:
        """Check if message appears to be RFC5424 format"""
        # RFC5424 messages start with <priority>version
        return re.match(r'^<\d+>\d+\s', message) is not None
    
    def _parse_rfc5424(self, message: str, source_ip: Optional[str] = None) -> SyslogMessage:
        """Parse RFC5424 format syslog message"""
        # RFC5424 format: <priority>version timestamp hostname app-name procid msgid structured-data msg
        # structured-data can be '-' or one/more bracket groups that may contain spaces
        pattern = r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|\[[^\]]*\](?:\s*\[[^\]]*\])*)\s*(.*)$'
        match = re.match(pattern, message)

        if not match:
            raise ValueError("Invalid RFC5424 format")

        priority = int(match.group(1))
        version = int(match.group(2))
        timestamp_str = match.group(3)
        hostname = match.group(4)
        app_name = match.group(5)
        proc_id = match.group(6)
        msg_id = match.group(7)
        structured_data_str = match.group(8)
        msg = match.group(9)

        # Parse priority into facility and severity
        facility = priority >> 3
        severity = priority & 0x07

        # Parse timestamp
        timestamp = self._parse_timestamp(timestamp_str)

        # Parse structured data
        structured_data = self._parse_structured_data(structured_data_str)

        return SyslogMessage(
            raw_message=message,
            format=SyslogFormat.RFC5424,
            timestamp=timestamp,
            hostname=hostname if hostname != '-' else None,
            source_ip=source_ip,
            facility=facility,
            severity=severity,
            priority=priority,
            program=app_name if app_name != '-' else None,
            process_id=proc_id if proc_id != '-' else None,
            message_id=msg_id if msg_id != '-' else None,
            message=msg.strip() if msg else None,
            structured_data=structured_data
        )
    
    def _parse_rfc3164(self, message: str, source_ip: Optional[str] = None) -> SyslogMessage:
        """Parse RFC3164 format syslog message"""
        # RFC3164 format: <priority>timestamp hostname program[pid]: message
        pattern = r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(\[(\d+)\])?\s*:\s*(.*)'
        match = re.match(pattern, message)
        
        if not match:
            # Try simplified format without program/pid
            pattern = r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)'
            match = re.match(pattern, message)
            
            if not match:
                raise ValueError("Invalid RFC3164 format")
            
            priority = int(match.group(1))
            timestamp_str = match.group(2)
            hostname = match.group(3)
            msg = match.group(4)
            program = None
            proc_id = None
        else:
            priority = int(match.group(1))
            timestamp_str = match.group(2)
            hostname = match.group(3)
            program = match.group(4)
            proc_id = match.group(6)
            msg = match.group(7)
        
        # Parse priority into facility and severity
        facility = priority >> 3
        severity = priority & 0x07
        
        # Parse timestamp
        timestamp = self._parse_timestamp(timestamp_str)
        
        return SyslogMessage(
            raw_message=message,
            format=SyslogFormat.RFC3164,
            timestamp=timestamp,
            hostname=hostname,
            source_ip=source_ip,
            facility=facility,
            severity=severity,
            priority=priority,
            program=program,
            process_id=proc_id,
            message=msg.strip() if msg else None
        )
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats"""
        try:
            # RFC5424 timestamp formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',          # 2023-12-01T10:30:45.123Z
                '%Y-%m-%dT%H:%M:%SZ',             # 2023-12-01T10:30:45Z
                '%Y-%m-%dT%H:%M:%S.%f%z',         # 2023-12-01T10:30:45.123+05:30
                '%Y-%m-%dT%H:%M:%S%z',            # 2023-12-01T10:30:45+05:30
                '%b %d %H:%M:%S',                 # RFC3164: Dec  1 10:30:45
                '%b  %d %H:%M:%S',                # RFC3164: Dec  1 10:30:45 (double space)
            ]
            
            for fmt in formats:
                try:
                    if fmt.startswith('%b'):
                        # RFC3164 format - add current year
                        timestamp_str = f"{datetime.now().year} {timestamp_str}"
                        fmt = f"%Y {fmt}"
                    
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            logger.warning(f"Unable to parse timestamp: {timestamp_str}")
            return None
            
        except Exception as e:
            logger.error(f"Error parsing timestamp {timestamp_str}: {e}")
            return None
    
    def _parse_structured_data(self, structured_data_str: str) -> Optional[Dict[str, Any]]:
        """Parse RFC5424 structured data"""
        if not structured_data_str or structured_data_str == '-':
            return None
        
        try:
            # Parse structured data elements: [id param1="value1" param2="value2"]
            structured_data = {}
            pattern = r'\[([^\]]+)\]'
            elements = re.findall(pattern, structured_data_str)
            
            for element in elements:
                parts = element.split(None, 1)
                if not parts:
                    continue
                
                element_id = parts[0]
                element_data = {}
                
                if len(parts) > 1:
                    # Parse parameters
                    param_pattern = r'(\w+)="([^"]*)"'
                    params = re.findall(param_pattern, parts[1])
                    element_data = dict(params)
                
                structured_data[element_id] = element_data
            
            return structured_data if structured_data else None
            
        except Exception as e:
            logger.error(f"Error parsing structured data {structured_data_str}: {e}")
            return None
    
    def get_stats(self) -> Dict[str, int]:
        """Get parser statistics"""
        return self.stats.copy()

class SyslogFacility:
    """Syslog facility constants and utilities"""
    
    FACILITIES = {
        0: "kernel",
        1: "user",
        2: "mail",
        3: "daemon",
        4: "auth",
        5: "syslog",
        6: "lpr",
        7: "news",
        8: "uucp",
        9: "cron",
        10: "authpriv",
        11: "ftp",
        16: "local0",
        17: "local1",
        18: "local2",
        19: "local3",
        20: "local4",
        21: "local5",
        22: "local6",
        23: "local7"
    }
    
    @classmethod
    def get_facility_name(cls, facility_code: int) -> str:
        """Get facility name from code"""
        return cls.FACILITIES.get(facility_code, f"unknown({facility_code})")

class SyslogSeverity:
    """Syslog severity constants and utilities"""
    
    SEVERITIES = {
        0: "emergency",
        1: "alert",
        2: "critical",
        3: "error",
        4: "warning",
        5: "notice",
        6: "info",
        7: "debug"
    }
    
    @classmethod
    def get_severity_name(cls, severity_code: int) -> str:
        """Get severity name from code"""
        return cls.SEVERITIES.get(severity_code, f"unknown({severity_code})")

# Global parser instance
parser = SyslogParser()
