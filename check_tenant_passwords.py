#!/usr/bin/env python3
"""Check tenant passwords for BITS-SIEM"""

import sys
import os
sys.path.append('/Users/aspundir/Documents/Bits/BITS-SIEM/api')

from config import config

def main():
    print("BITS-SIEM Tenant Password Check")
    print("=" * 40)
    
    tenant_configs = config.get_sample_tenant_configs()
    
    print("Available tenants and their passwords:")
    for tenant_id, tenant_config in tenant_configs.items():
        password = tenant_config['password']
        name = tenant_config['metadata']['name']
        print(f"• {name} ({tenant_id})")
        print(f"  Email: admin@{tenant_id.replace('-', '')}.com")
        print(f"  Password: {password}")
        print()

if __name__ == "__main__":
    main()
