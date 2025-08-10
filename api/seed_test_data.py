#!/usr/bin/env python3
"""
BITS-SIEM Test Dataset Seeder
=============================

Generates realistic multi-tenant test data to exercise:
- AuthenticationEvent patterns (normal, brute-force, distributed attempts)
- UserBehaviorBaseline creation
- Default DetectionRule initialization per tenant

Usage:
  python seed_test_data.py              # Seed all known tenants
  python seed_test_data.py acme-corp    # Seed specific tenant

Notes:
- Run from the api/ directory so local imports resolve (same as init_database.py).
- Requires a running PostgreSQL and DATABASE_URL configured.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from random import randint, choice

from database import (
    DATABASE_AVAILABLE,
    SessionLocal,
    init_db,
    Tenant,
    User,
    AuthenticationEvent,
    UserBehaviorBaseline,
)

try:
    from bruteforce_detection import initialize_default_detection_rules, BehavioralAnalyzer
except Exception:
    # Optional: continue without rule initialization/baseline building
    initialize_default_detection_rules = None
    BehavioralAnalyzer = None


def ensure_core_data(db) -> None:
    """Ensure base tenants/users/sources/notifications exist via init_db()."""
    init_db()


def get_or_create_user(db, tenant_id: str, email: str, name: str, role: str = "user") -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        return user
    user = User(
        id=email,
        email=email,
        name=name,
        password="demo123",
        role=role,
        tenant_id=tenant_id,
        tenants_access=[tenant_id],
    )
    db.add(user)
    db.commit()
    return user


def seed_normal_activity(db, tenant_id: str, user: User, days: int = 14) -> None:
    """Generate normal login patterns for baseline learning."""
    now = datetime.utcnow()
    for d in range(days, 0, -1):
        day = now - timedelta(days=d)
        # 1-3 logins within business hours
        logins_today = randint(1, 3)
        for _ in range(logins_today):
            hour = choice([9, 10, 11, 14, 15, 16])
            ts = day.replace(hour=hour, minute=randint(0, 59), second=randint(0, 59), microsecond=0)
            evt = AuthenticationEvent(
                tenant_id=tenant_id,
                user_id=user.id,
                username=user.email,
                event_type="login_success",
                source_type="web",
                source_ip="192.168.1.101",
                source_port=443,
                user_agent="Mozilla/5.0",
                country="US",
                city="San Jose",
                device_fingerprint="device-01",
                session_id=f"sess-{user.id}-{ts.timestamp()}",
                login_duration=randint(30, 600),
                failed_attempts_count=0,
                time_since_last_attempt=randint(60, 600),
                metadata={"method": "password"},
                timestamp=ts,
            )
            db.add(evt)
        # Occasional single failure
        if randint(0, 4) == 0:
            tsf = day.replace(hour=choice([8, 18]), minute=randint(0, 59), second=randint(0, 59), microsecond=0)
            db.add(AuthenticationEvent(
                tenant_id=tenant_id,
                user_id=user.id,
                username=user.email,
                event_type="login_failure",
                source_type="web",
                source_ip="192.0.2.10",
                source_port=443,
                user_agent="Mozilla/5.0",
                country="US",
                city="San Jose",
                device_fingerprint="device-01",
                session_id=None,
                login_duration=0,
                failed_attempts_count=1,
                time_since_last_attempt=None,
                metadata={"reason": "bad_password"},
                timestamp=tsf,
            ))
    db.commit()


def seed_bruteforce_burst(db, tenant_id: str, user: User, failures: int = 6) -> None:
    """Generate a burst of failed logins from a single IP within 5 minutes."""
    base = datetime.utcnow() - timedelta(minutes=2)
    attacker_ip = "203.0.113.10"
    for i in range(failures):
        ts = base + timedelta(seconds=i * 30)
        db.add(AuthenticationEvent(
            tenant_id=tenant_id,
            user_id=user.id,
            username=user.email,
            event_type="login_failure",
            source_type="web",
            source_ip=attacker_ip,
            source_port=443,
            user_agent="curl/8.0",
            country="US",
            city="",
            device_fingerprint=None,
            session_id=None,
            login_duration=0,
            failed_attempts_count=i + 1,
            time_since_last_attempt=30 if i else None,
            metadata={"reason": "bad_password", "burst": True},
            timestamp=ts,
        ))
    # Optional suspicious success after failures
    success_ts = base + timedelta(minutes=3)
    db.add(AuthenticationEvent(
        tenant_id=tenant_id,
        user_id=user.id,
        username=user.email,
        event_type="login_success",
        source_type="web",
        source_ip=attacker_ip,
        source_port=443,
        user_agent="curl/8.0",
        country="US",
        city="",
        device_fingerprint="unknown",
        session_id=f"sess-{user.id}-{success_ts.timestamp()}",
        login_duration=60,
        failed_attempts_count=0,
        time_since_last_attempt=60,
        metadata={"note": "success-after-failures"},
        timestamp=success_ts,
    ))
    db.commit()


def seed_distributed_failures(db, tenant_id: str, user: User, total_failures: int = 9) -> None:
    """Generate distributed failures across multiple IPs within a short window."""
    base = datetime.utcnow() - timedelta(minutes=10)
    attacker_ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    for i in range(total_failures):
        ts = base + timedelta(seconds=i * 40)
        db.add(AuthenticationEvent(
            tenant_id=tenant_id,
            user_id=user.id,
            username=user.email,
            event_type="login_failure",
            source_type="ssh",
            source_ip=choice(attacker_ips),
            source_port=22,
            user_agent="OpenSSH",
            country="DE",
            city="",
            device_fingerprint=None,
            session_id=None,
            login_duration=0,
            failed_attempts_count=1,
            time_since_last_attempt=40 if i else None,
            metadata={"reason": "bad_password", "distributed": True},
            timestamp=ts,
        ))
    db.commit()


def build_baselines_and_rules(db, tenant_id: str, users: list[User]) -> None:
    if initialize_default_detection_rules:
        try:
            initialize_default_detection_rules(tenant_id, db)
        except Exception:
            pass
    if BehavioralAnalyzer:
        analyzer = BehavioralAnalyzer(db)
        for user in users:
            try:
                analyzer.build_user_baseline(tenant_id, user.id, user.email, lookback_days=30)
            except Exception:
                # If baseline exists or insufficient data, ignore
                pass


def seed_for_tenant(db, tenant_id: str) -> None:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        print(f"⚠️  Tenant '{tenant_id}' not found, skipping")
        return

    # Choose or create demo users in this tenant
    primary_email = "user@acme.com" if tenant_id == "acme-corp" else f"user@{tenant_id}.com"
    user = db.query(User).filter(User.tenant_id == tenant_id, User.email == primary_email).first()
    if not user:
        user = get_or_create_user(db, tenant_id, primary_email, name=f"{tenant.name} User", role="user")

    # Normal activity for baseline
    seed_normal_activity(db, tenant_id, user, days=14)

    # Attack patterns
    seed_bruteforce_burst(db, tenant_id, user, failures=6)
    seed_distributed_failures(db, tenant_id, user, total_failures=9)

    # Baselines and default rules
    build_baselines_and_rules(db, tenant_id, [user])

    print(f"✅ Seeded test data for tenant: {tenant_id}")


def main(argv: list[str]) -> int:
    if not DATABASE_AVAILABLE or SessionLocal is None:
        print("❌ Database not available. Ensure PostgreSQL is running and DATABASE_URL is set.")
        return 1

    ensure_core_data(SessionLocal())
    db = SessionLocal()
    try:
        if len(argv) > 1:
            tenants = argv[1:]
        else:
            tenants = [t.id for t in db.query(Tenant.id).all()]

        for tenant_id in tenants:
            seed_for_tenant(db, tenant_id)

        print("\n🎯 Test dataset seeding complete.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
