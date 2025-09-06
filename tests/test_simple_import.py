#!/usr/bin/env python3
"""
Very simple test to verify the circular import issue is resolved
"""

import sys
import os

# Add the processing directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'processing'))

def test_core_import():
    """Test that the core modules can be imported without circular import errors"""
    
    print("Testing core module imports...")
    
    try:
        # Test threat_models import (this should always work)
        print("Importing threat_models...")
        from threat_models import ThreatAlert
        print("✅ threat_models imported successfully")
        
        # Test that ThreatAlert works
        print("Testing ThreatAlert creation...")
        alert = ThreatAlert(
            id="test_1",
            tenant_id="demo-org", 
            alert_type="test",
            severity="info",
            title="Test",
            description="Test alert",
            source_ip="127.0.0.1"
        )
        print("✅ ThreatAlert created successfully")
        
        # Test that we can import threat_detection module without circular import
        print("Importing threat_detection module...")
        import threat_detection
        print("✅ threat_detection module imported successfully")
        
        # Check that ThreatAlert is available and working
        print("Testing ThreatAlert serialization...")
        alert_dict = alert.to_dict()
        assert 'id' in alert_dict
        assert 'timestamp' in alert_dict
        print("✅ ThreatAlert serialization working")
        
        print("\n🎉 SUCCESS: Circular import issue is resolved!")
        print("The core modules can be imported without dependency issues.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("This indicates a circular import or missing dependency issue.")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("BITS-SIEM Circular Import Fix Test")
    print("=" * 40)
    
    if test_core_import():
        print("\n✅ Test PASSED: Circular import issue is fixed!")
        sys.exit(0)
    else:
        print("\n❌ Test FAILED: Circular import issue still exists!")
        sys.exit(1)
