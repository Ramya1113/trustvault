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


def test_unknown_username_runs_dummy_password_hash_check(test_setup, monkeypatch):
    """Verify that check_password_hash is invoked against _DUMMY_PASSWORD_HASH when user is unknown."""
    app, org = test_setup
    client = app.test_client()

    called_with = []
    from werkzeug.security import check_password_hash as original_check

    def mock_check(p_hash, password):
        called_with.append((p_hash, password))
        return original_check(p_hash, password)

    monkeypatch.setattr('app.blueprints.auth.check_password_hash', mock_check)

    from app.blueprints.auth import _DUMMY_PASSWORD_HASH

    resp = client.post('/auth/login', data={
        'username': 'nonexistent_user',
        'password': 'AttemptedSecretPassword123!'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert len(called_with) == 1
    assert called_with[0][0] == _DUMMY_PASSWORD_HASH
    assert called_with[0][1] == 'AttemptedSecretPassword123!'


def test_username_log_sanitization_and_truncation(test_setup, caplog):
    """Verify that control characters are escaped and oversized usernames are truncated in log lines."""
    app, org = test_setup
    client = app.test_client()

    # 1. CRLF log injection attempt
    crlf_username = "hacker\r\nINJECTED_LOG_ENTRY"
    with caplog.at_level(logging.WARNING):
        client.post('/auth/login', data={
            'username': crlf_username,
            'password': 'BadPassword123!'
        }, follow_redirects=True)

    log_messages = [record.message for record in caplog.records if record.levelno == logging.WARNING]
    # Ensure raw newlines/returns are not in the logged message
    assert any("hacker\\r\\nINJECTED_LOG_ENTRY" in msg for msg in log_messages)
    assert not any("hacker\r\nINJECTED_LOG_ENTRY" in msg for msg in log_messages)

    # 2. Oversized username truncation (> 64 characters)
    long_username = "X" * 120
    with caplog.at_level(logging.WARNING):
        client.post('/auth/login', data={
            'username': long_username,
            'password': 'BadPassword123!'
        }, follow_redirects=True)

    log_messages_2 = [record.message for record in caplog.records if record.levelno == logging.WARNING]
    expected_truncated = ("X" * 64) + "..."
    assert any(f"'{expected_truncated}'" in msg for msg in log_messages_2)


def test_lockout_dict_expiration_and_capacity_cap():
    """Verify that the lockout tracker expires stale entries and caps memory growth."""
    from datetime import datetime, timezone, timedelta
    from app.blueprints.auth import (
        _failed_login_attempts, _lockout_lock,
        record_failed_attempt, is_account_locked,
        _cleanup_expired_lockouts_locked, MAX_LOCKOUT_ENTRIES
    )

    with _lockout_lock:
        _failed_login_attempts.clear()

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(minutes=15)

    # 1. Test expiration
    with _lockout_lock:
        _failed_login_attempts['stale_user'] = [old_time, old_time]
        _failed_login_attempts['fresh_user'] = [now]
        _cleanup_expired_lockouts_locked(now)

        assert 'stale_user' not in _failed_login_attempts
        assert 'fresh_user' in _failed_login_attempts

    # 2. Test is_account_locked auto-prunes expired keys
    with _lockout_lock:
        _failed_login_attempts['expired_lockout'] = [old_time] * 6
    assert not is_account_locked('expired_lockout')
    assert 'expired_lockout' not in _failed_login_attempts

    # 3. Test capacity cap enforcement
    with _lockout_lock:
        _failed_login_attempts.clear()
        # Seed dictionary up to MAX_LOCKOUT_ENTRIES
        for i in range(MAX_LOCKOUT_ENTRIES):
            _failed_login_attempts[f'user_{i}'] = [now]

    # Recording a new failed attempt must evict an older key so length stays <= MAX_LOCKOUT_ENTRIES
    record_failed_attempt('overflow_user')

    with _lockout_lock:
        assert len(_failed_login_attempts) <= MAX_LOCKOUT_ENTRIES
        assert 'overflow_user' in _failed_login_attempts
        _failed_login_attempts.clear()

