import os
import pytest

DATABASE_URL = os.getenv("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="Database not configured; set DATABASE_URL to run integration tests",
)


def test_seed_minimum_entities():
    from database import DATABASE_AVAILABLE, SessionLocal, Tenant, User, AuthenticationEvent

    assert DATABASE_AVAILABLE, "Database engine not available"
    db = SessionLocal()
    try:
        tenants = db.query(Tenant).all()
        assert len(tenants) >= 1, "No tenants found after seeding"

        users = db.query(User).all()
        assert len(users) >= 1, "No users found after seeding"

        events = db.query(AuthenticationEvent).order_by(AuthenticationEvent.timestamp.desc()).limit(10).all()
        assert len(events) >= 1, "No authentication events present"
    finally:
        db.close()


def test_bruteforce_pattern_present():
    from database import SessionLocal, AuthenticationEvent
    db = SessionLocal()
    try:
        # Look for the burst IP we use in seed script
        attacker_ip = "203.0.113.10"
        failures = (
            db.query(AuthenticationEvent)
            .filter(
                AuthenticationEvent.source_ip == attacker_ip,
                AuthenticationEvent.event_type == "login_failure",
            )
            .count()
        )
        assert failures >= 5, "Expected >=5 failures for bruteforce burst"
    finally:
        db.close()
