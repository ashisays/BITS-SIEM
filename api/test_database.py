#!/usr/bin/env python3
"""
Quick test script to verify database integration works
"""

def test_database():
    try:
        from database_working import DATABASE_AVAILABLE, init_db, SessionLocal
        from database_working import Tenant, User, Source, Notification, Report
        
        print("🧪 Testing Database Integration")
        print("=" * 40)
        
        if not DATABASE_AVAILABLE:
            print("❌ Database not available")
            return False
        
        print("✅ Database modules imported successfully")
        
        # Test database initialization
        success = init_db()
        if success:
            print("✅ Database initialization successful")
        else:
            print("❌ Database initialization failed")
            return False
        
        # Test database queries
        if SessionLocal:
            db = SessionLocal()
            
            # Test tenant count
            tenant_count = db.query(Tenant).count()
            print(f"✅ Found {tenant_count} tenants")
            
            # Test user count
            user_count = db.query(User).count()
            print(f"✅ Found {user_count} users")
            
            # Test source count
            source_count = db.query(Source).count()
            print(f"✅ Found {source_count} sources")
            
            # Test notification count (with meta_data field)
            notification_count = db.query(Notification).count()
            print(f"✅ Found {notification_count} notifications")
            
            # Test notification field access
            notifications = db.query(Notification).limit(3).all()
            for notif in notifications:
                print(f"   📧 {notif.message[:50]}...")
                if notif.meta_data:
                    print(f"      Details: {notif.meta_data}")
            
            # Test report count
            report_count = db.query(Report).count()
            print(f"✅ Found {report_count} reports")
            
            db.close()
        
        print("\n🎉 All database tests passed!")
        print("Database integration is working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_database()
