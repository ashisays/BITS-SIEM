#!/usr/bin/env python3
"""
Test script to verify SRE user exists in database
"""

def test_sre_user():
    try:
        print("🧪 Testing SRE User in Database")
        print("=" * 40)
        
        from database import DATABASE_AVAILABLE, SessionLocal, User, Tenant
        
        if not DATABASE_AVAILABLE:
            print("❌ Database not available - using fallback mode")
            from app import fallback_users
            sre_user = fallback_users.get("sre@bits.com")
            if sre_user:
                print("✅ SRE user found in fallback data:")
                print(f"   Email: {sre_user['email']}")
                print(f"   Name: {sre_user['name']}")
                print(f"   Role: {sre_user['role']}")
                print(f"   Tenant: {sre_user['tenantId']}")
                print(f"   Multi-tenant access: {sre_user['tenants']}")
            else:
                print("❌ SRE user not found in fallback data")
            return
        
        print("✅ Database is available, checking for SRE user...")
        
        db = SessionLocal()
        
        # Check BITS Internal tenant
        bits_tenant = db.query(Tenant).filter(Tenant.id == "bits-internal").first()
        if bits_tenant:
            print(f"✅ BITS Internal tenant found: {bits_tenant.name}")
        else:
            print("❌ BITS Internal tenant not found")
        
        # Check SRE user
        sre_user = db.query(User).filter(User.email == "sre@bits.com").first()
        if sre_user:
            print("✅ SRE user found in database:")
            print(f"   Email: {sre_user.email}")
            print(f"   Name: {sre_user.name}")
            print(f"   Role: {sre_user.role}")
            print(f"   Tenant: {sre_user.tenant_id}")
            print(f"   Multi-tenant access: {sre_user.tenants_access}")
            print(f"   Active: {sre_user.is_active}")
        else:
            print("❌ SRE user not found in database")
            print("🔧 Trying to create SRE user...")
            
            from database import init_db
            success = init_db()
            if success:
                print("✅ Database re-initialization completed")
                # Check again
                sre_user = db.query(User).filter(User.email == "sre@bits.com").first()
                if sre_user:
                    print("✅ SRE user now exists after re-initialization")
                else:
                    print("❌ SRE user still missing after re-initialization")
            else:
                print("❌ Database re-initialization failed")
        
        # Count all users
        total_users = db.query(User).count()
        print(f"📊 Total users in database: {total_users}")
        
        # List all users
        all_users = db.query(User).all()
        print("👥 All users:")
        for user in all_users:
            print(f"   - {user.name} ({user.email}) - {user.role}")
        
        db.close()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_sre_user()
