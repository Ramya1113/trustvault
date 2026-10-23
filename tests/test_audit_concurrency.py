"""
Test for Issue 3: Concurrency-safe log_event with per-organization locks.
Tests that multiple concurrent threads logging to the same organization produce
a valid, unbroken cryptographic hash chain.
"""
import threading
import pytest
from sqlalchemy.pool import StaticPool
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User, AuditLog
from app.audit import log_event, verify_chain


class ConcurrencyTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'poolclass': StaticPool,
        'connect_args': {'check_same_thread': False}
    }
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(ConcurrencyTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_concurrent_log_event_with_two_threads(app):
    """
    Spawn two concurrent threads that concurrently log events to the same organization.
    Verify that per-org locking prevents race conditions and produces a valid hash chain.
    """
    with app.app_context():
        org = Organization(name="Concurrent Corp")
        db.session.add(org)
        db.session.commit()
        org_id = org.id

        user = User(org_id=org_id, username="thread_user", email="thread@corp.com", role="admin")
        user.set_password("Password123!")
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    def worker(thread_idx, count):
        # Each thread gets its own application context
        with app.app_context():
            for i in range(count):
                log_event(
                    actor=user_id,
                    action=f"thread.{thread_idx}.action_{i}",
                    target_type="system",
                    target_id=i,
                    outcome="allowed",
                    detail=f"Thread {thread_idx} log entry {i}",
                    org_id=org_id
                )

    # Spawn 2 concurrent threads logging 15 events each
    t1 = threading.Thread(target=worker, args=(1, 15))
    t2 = threading.Thread(target=worker, args=(2, 15))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    with app.app_context():
        # Confirm all 30 events were persisted
        total_logs = AuditLog.query.filter_by(org_id=org_id).count()
        assert total_logs == 30

        # Cryptographically verify the entire chain
        is_valid, broken_id = verify_chain(org_id)
        assert is_valid is True, f"Hash chain broken at entry id={broken_id}"
        assert broken_id is None
