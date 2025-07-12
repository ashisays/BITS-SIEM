#!/usr/bin/env python3
"""
BITS-SIEM Database Initialization Script

This script initializes the PostgreSQL database with sample data
and can be used by other services to access the same data.

Usage:
    python init_database.py

Environment Variables:
    DATABASE_URL: PostgreSQL connection string
    Default: postgresql+psycopg2://siem:siempassword@db:5432/siemdb
"""

import sys
import os
from database import init_db, DATABASE_AVAILABLE, SessionLocal
from database import Tenant, User, Source, Notification, Report

def main():
    print("BITS-SIEM Database Initialization")
    print("=" * 40)
    
    if not DATABASE_AVAILABLE:
        print("❌ Database not available. Check your PostgreSQL connection.")
        print("   Ensure PostgreSQL is running and DATABASE_URL is correct.")
        sys.exit(1)
    
    print(f"🔗 Database URL: {os.getenv('DATABASE_URL', 'postgresql+psycopg2://siem:siempassword@db:5432/siemdb').replace('siempassword', '***')}")
    
    try:
        success = init_db()
        if success:
            print("✅ Database initialized successfully!")
            
            # Show summary of data
            if SessionLocal:
                db = SessionLocal()
                
                tenant_count = db.query(Tenant).count()
                user_count = db.query(User).count()
                source_count = db.query(Source).count()
                notification_count = db.query(Notification).count()
                report_count = db.query(Report).count()
                
                print("\n📊 Database Summary:")
                print(f"   Tenants: {tenant_count}")
                print(f"   Users: {user_count}")
                print(f"   Sources: {source_count}")
                print(f"   Notifications: {notification_count}")
                print(f"   Reports: {report_count}")
                
                print("\n🏢 Available Organizations:")
                tenants = db.query(Tenant).all()
                for tenant in tenants:
                    print(f"   • {tenant.name} ({tenant.id})")
                    users = db.query(User).filter(User.tenant_id == tenant.id).all()
                    for user in users:
                        print(f"     - {user.name} ({user.email}) - {user.role}")
                
                db.close()
                
            print("\n🎯 Next Steps:")
            print("   1. Start the BITS-SIEM API server")
            print("   2. Other services can connect to the same database")
            print("   3. Use the same DATABASE_URL in all services")
            
            print("\n🚀 Ready for multi-service deployment!")
            
        else:
            print("❌ Database initialization failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"💥 Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
