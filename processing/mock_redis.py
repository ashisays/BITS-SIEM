"""
Mock Redis implementation for testing without Redis server
"""

import json
import time
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict

class MockRedis:
    """Mock Redis client for testing purposes"""
    
    def __init__(self, host=None, port=None, db=None, password=None, decode_responses=True):
        self.data = defaultdict(dict)  # For hash operations
        self.strings = {}  # For string operations
        self.sets = defaultdict(set)  # For set operations
        self.lists = defaultdict(list)  # For list operations
        self.streams = defaultdict(list)  # For stream operations
        self.expiry = {}  # Track expiration times
        self.decode_responses = decode_responses
    
    def ping(self):
        """Mock ping - always succeeds"""
        return True
    
    def get(self, key: str) -> Optional[str]:
        """Get string value"""
        if self._is_expired(key):
            return None
        return self.strings.get(key)
    
    def set(self, key: str, value: str) -> bool:
        """Set string value"""
        self.strings[key] = value
        return True
    
    def setex(self, key: str, time_seconds: int, value: str) -> bool:
        """Set string value with expiration"""
        self.strings[key] = value
        self.expiry[key] = int(time.time()) + time_seconds
        return True
    
    def incr(self, key: str) -> int:
        """Increment counter"""
        current = int(self.strings.get(key, 0))
        current += 1
        self.strings[key] = str(current)
        return current
    
    def expire(self, key: str, time_seconds: int) -> bool:
        """Set expiration time"""
        self.expiry[key] = int(time.time()) + time_seconds
        return True
    
    def ttl(self, key: str) -> int:
        """Get time to live"""
        if key in self.expiry:
            remaining = self.expiry[key] - int(time.time())
            return max(0, remaining)
        return -1
    
    def delete(self, *keys) -> int:
        """Delete keys"""
        deleted = 0
        for key in keys:
            if key in self.strings:
                del self.strings[key]
                deleted += 1
            if key in self.data:
                del self.data[key]
                deleted += 1
            if key in self.sets:
                del self.sets[key]
                deleted += 1
            if key in self.lists:
                del self.lists[key]
                deleted += 1
            if key in self.expiry:
                del self.expiry[key]
        return deleted
    
    def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        # Simple pattern matching - just check if pattern (without *) is in key
        pattern_clean = pattern.replace('*', '')
        matching_keys = []
        
        for key in self.strings.keys():
            if pattern_clean in key:
                matching_keys.append(key)
        
        for key in self.data.keys():
            if pattern_clean in key:
                matching_keys.append(key)
                
        for key in self.sets.keys():
            if pattern_clean in key:
                matching_keys.append(key)
                
        for key in self.lists.keys():
            if pattern_clean in key:
                matching_keys.append(key)
        
        return matching_keys
    
    # Hash operations
    def hset(self, key: str, field: str, value: str) -> int:
        """Set hash field"""
        if key not in self.data:
            self.data[key] = {}
        self.data[key][field] = value
        return 1
    
    def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field"""
        if self._is_expired(key):
            return None
        return self.data.get(key, {}).get(field)
    
    def hgetall(self, key: str) -> Dict[str, str]:
        """Get all hash fields"""
        if self._is_expired(key):
            return {}
        return self.data.get(key, {})
    
    def hdel(self, key: str, *fields) -> int:
        """Delete hash fields"""
        if key not in self.data:
            return 0
        
        deleted = 0
        for field in fields:
            if field in self.data[key]:
                del self.data[key][field]
                deleted += 1
        
        # Remove key if no fields left
        if not self.data[key]:
            del self.data[key]
        
        return deleted
    
    # Set operations
    def sadd(self, key: str, *values) -> int:
        """Add to set"""
        added = 0
        for value in values:
            if value not in self.sets[key]:
                self.sets[key].add(value)
                added += 1
        return added
    
    def scard(self, key: str) -> int:
        """Get set cardinality"""
        if self._is_expired(key):
            return 0
        return len(self.sets.get(key, set()))
    
    def smembers(self, key: str) -> Set[str]:
        """Get set members"""
        if self._is_expired(key):
            return set()
        return self.sets.get(key, set()).copy()
    
    def sismember(self, key: str, value: str) -> bool:
        """Check set membership"""
        if self._is_expired(key):
            return False
        return value in self.sets.get(key, set())
    
    # List operations
    def lpush(self, key: str, *values) -> int:
        """Push to list (left)"""
        for value in reversed(values):
            self.lists[key].insert(0, value)
        return len(self.lists[key])
    
    def lrange(self, key: str, start: int, end: int) -> List[str]:
        """Get list range"""
        if self._is_expired(key):
            return []
        
        lst = self.lists.get(key, [])
        if end == -1:
            return lst[start:]
        return lst[start:end+1]
    
    # Stream operations (simplified)
    def xadd(self, key: str, fields: Dict[str, Any], id: str = "*") -> str:
        """Add to stream"""
        import uuid
        entry_id = str(uuid.uuid4()) if id == "*" else id
        entry = {"id": entry_id, "fields": fields}
        self.streams[key].append(entry)
        return entry_id
    
    def _is_expired(self, key: str) -> bool:
        """Check if key is expired"""
        if key in self.expiry:
            if int(time.time()) > self.expiry[key]:
                # Clean up expired key
                self._cleanup_expired_key(key)
                return True
        return False
    
    def _cleanup_expired_key(self, key: str):
        """Clean up expired key from all data structures"""
        self.strings.pop(key, None)
        self.data.pop(key, None)
        self.sets.pop(key, None)
        self.lists.pop(key, None)
        self.streams.pop(key, None)
        self.expiry.pop(key, None)

# Create a mock redis module
class MockRedisModule:
    """Mock redis module"""
    
    @staticmethod
    def Redis(*args, **kwargs):
        return MockRedis(*args, **kwargs)

# Function to get Redis client (real or mock)
def get_redis_client(**kwargs):
    """Get Redis client - real if available, mock otherwise"""
    try:
        import redis
        return redis.Redis(**kwargs)
    except ImportError:
        return MockRedis(**kwargs)
