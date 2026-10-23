"""
Integration tests for Issue 8:
- Handling of failed logins for unknown usernames.
- Verify generic error message returned (prevents username enumeration).
- Verify structured warning logged via current_app.logger without polluting tenant audit log.
- Verify rate-limiting lockout triggers after 5 failed attempts for unknown usernames.
"""

import logging
import pytest
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User, AuditLog
from app.blueprints.auth import clear_failed_attempts


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def test_setup():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()

        org = Organization(name="Audit Test Org")
        db.session.add(org)
        db.session.commit()

        # Clean lockout tracker
        clear_failed_attempts("ghostuser")
        clear_failed_attempts("validuser")

        yield app, org
        clear_failed_attempts("ghostuser")
        clear_failed_attempts("validuser")
        db.session.remove()
        db.drop_all()


def test_unknown_username_failed_login_logging_and_enumeration_defense(test_setup, caplog):
    """
    Test that an unknown username:
    1. Returns generic error message without disclosing user non-existence.
    2. Logs a security warning in current_app.logger with IP and username.
    3. Does NOT insert any record into the tenant audit log.
    """
    app, org = test_setup
    client = app.test_client()

    with caplog.at_level(logging.WARNING):
        resp = client.post('/auth/login', data={
            'username': 'ghostuser',
            'password': 'SomeRandomPassword123!'
        }, follow_redirects=True)

    # 1. Generic error message
    assert resp.status_code == 200
    assert b"Invalid username or password." in resp.data

    # 2. Structured log warning captured
    log_messages = [record.message for record in caplog.records if record.levelno == logging.WARNING]
    assert any("Failed login attempt for non-existent username 'ghostuser'" in msg for msg in log_messages)

    # 3. Tenant audit log remains empty / unpolluted
    with app.app_context():
        audit_count = AuditLog.query.count()
        assert audit_count == 0, "No audit log entry should be created for non-existent user"


def test_unknown_username_rate_limiting_lockout(test_setup, caplog):
    """
    Test that unknown usernames are also subject to brute-force rate-limiting (lockout after 5 attempts).
    """
    app, org = test_setup
    client = app.test_client()

    # Attempt 5 failed logins for ghostuser
    for _ in range(5):
        resp = client.post('/auth/login', data={
            'username': 'ghostuser',
            'password': 'WrongPassword123!'
        })
        assert resp.status_code == 200

    # 6th attempt must trigger HTTP 429 lockout
    with caplog.at_level(logging.WARNING):
        locked_resp = client.post('/auth/login', data={
            'username': 'ghostuser',
            'password': 'AnyPassword123!'
        })
    assert locked_resp.status_code == 429
    assert b"Account temporarily locked" in locked_resp.data

    # Verify lockout warning was logged
    log_messages = [record.message for record in caplog.records if record.levelno == logging.WARNING]
    assert any("Login blocked due to lockout for non-existent username 'ghostuser'" in msg for msg in log_messages)
