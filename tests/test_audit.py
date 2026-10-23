"""
Tests for tamper-evident, hash-chained audit logging in app/audit.py.
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, AuditLog
from app.audit import log_event, verify_chain
from config import Config


class AuditTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create test application and in-memory database."""
    app = create_app(AuditTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_audit_log_five_events_chain_valid(app):
    """
    Test requirement: Log 5 events -> verify_chain returns (True, None).
    """
    with app.app_context():
        org = Organization(name="Audit Test Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="auditor", email="auditor@example.com", role="admin")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

        # Log 5 consecutive events
        events = [
            ("document.create", "document", 1, "allowed", "Created doc 1"),
            ("document.view", "document", 1, "allowed", "Viewed doc 1"),
            ("access.grant", "access_grant", 10, "allowed", "Granted read access"),
            ("document.edit", "document", 1, "denied", "Unauthorized edit attempt"),
            ("document.delete", "document", 1, "allowed", "Soft-deleted doc 1"),
        ]

        logged_records = []
        for action, target_type, target_id, outcome, detail in events:
            entry = log_event(
                actor=user,
                action=action,
                target_type=target_type,
                target_id=target_id,
                outcome=outcome,
                detail=detail
            )
            logged_records.append(entry)

        assert len(logged_records) == 5

        # Genesis record should have prev_hash as None
        assert logged_records[0].prev_hash is None
        # Each subsequent record should point to the previous record's entry_hash
        for i in range(1, 5):
            assert logged_records[i].prev_hash == logged_records[i - 1].entry_hash

        # Verify the entire chain
        ok, broken_id = verify_chain(org.id)
        assert ok is True
        assert broken_id is None


def test_tampered_row_in_db_fails_verify_chain(app):
    """
    Test requirement: Modify one row directly in the DB -> verify_chain fails and returns the broken id.
    """
    with app.app_context():
        org = Organization(name="Tamper Test Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="tamper_user", email="tamper@example.com", role="owner")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

        # Log 5 events
        entries = []
        for i in range(1, 6):
            e = log_event(
                actor=user,
                action=f"action.{i}",
                target_type="document",
                target_id=i,
                outcome="allowed",
                detail=f"Original detail {i}"
            )
            entries.append(e)

        # Confirm chain is initially intact
        ok, broken_id = verify_chain(org.id)
        assert ok is True
        assert broken_id is None

        # Directly tamper with row #3 directly in the DB via raw SQL
        target_tamper_id = entries[2].id
        db.session.execute(
            db.text("UPDATE audit_logs SET detail = 'TAMPERED DETAIL' WHERE id = :target_id"),
            {'target_id': target_tamper_id}
        )
        db.session.commit()

        # Chain verification MUST fail and identify the tampered record
        ok_tampered, broken_id_tampered = verify_chain(org.id)
        assert ok_tampered is False
        assert broken_id_tampered == target_tamper_id


def test_audit_log_append_only_enforced_by_orm(app):
    """
    Verify that AuditLog is strictly append-only:
    Attempting to update or delete through SQLAlchemy ORM raises RuntimeError.
    """
    with app.app_context():
        org = Organization(name="Append Only Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="append_user", email="append@example.com", role="owner")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

        entry = log_event(
            actor=user,
            action="test.immutable",
            target_type="document",
            target_id=1,
            outcome="allowed",
            detail="Immutable record"
        )

        # Attempting to update via ORM must raise RuntimeError
        entry.detail = "Unauthorized modification attempt"
        with pytest.raises(RuntimeError, match="modifying audit log entries is strictly forbidden"):
            db.session.commit()
        db.session.rollback()

        # Attempting to delete via ORM must raise RuntimeError
        entry = db.session.get(AuditLog, entry.id)
        db.session.delete(entry)
        with pytest.raises(RuntimeError, match="deleting audit log entries is strictly forbidden"):
            db.session.commit()
        db.session.rollback()


def test_auth_login_success_and_logout_creates_audit_trail(client, app):
    """
    Verify that login success and logout append valid audit log entries.
    """
    with app.app_context():
        org = Organization(name="Auth Audit Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="auth_audit_user", email="aau@example.com", role="viewer")
        user.set_password("GoodPassword123!")
        db.session.add(user)
        db.session.commit()
        org_id = org.id

    # 1. Login success
    login_resp = client.post('/auth/login', data={
        'username': 'auth_audit_user',
        'password': 'GoodPassword123!'
    }, follow_redirects=True)
    assert login_resp.status_code == 200

    with app.app_context():
        logs = AuditLog.query.filter_by(org_id=org_id).order_by(AuditLog.id.asc()).all()
        assert len(logs) == 1
        assert logs[0].action == "auth.login"
        assert logs[0].outcome == "allowed"
        assert logs[0].actor_id is not None

        # Verify chain
        ok, broken_id = verify_chain(org_id)
        assert ok is True
        assert broken_id is None

    # 2. Logout
    logout_resp = client.get('/auth/logout', follow_redirects=True)
    assert logout_resp.status_code == 200

    with app.app_context():
        logs = AuditLog.query.filter_by(org_id=org_id).order_by(AuditLog.id.asc()).all()
        assert len(logs) == 2
        assert logs[1].action == "auth.logout"
        assert logs[1].outcome == "allowed"
        assert logs[1].prev_hash == logs[0].entry_hash

        # Verify chain
        ok, broken_id = verify_chain(org_id)
        assert ok is True
        assert broken_id is None


def test_auth_login_failure_creates_denied_audit_log(client, app):
    """
    Verify that failed login attempts on existing accounts record DENIED audit logs.
    """
    with app.app_context():
        org = Organization(name="Fail Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="fail_user", email="fail@example.com", role="viewer")
        user.set_password("CorrectPassword123!")
        db.session.add(user)
        db.session.commit()
        org_id = org.id

    # Bad password attempt
    fail_resp = client.post('/auth/login', data={
        'username': 'fail_user',
        'password': 'IncorrectPassword!'
    }, follow_redirects=True)
    assert fail_resp.status_code == 200

    with app.app_context():
        logs = AuditLog.query.filter_by(org_id=org_id).all()
        assert len(logs) == 1
        assert logs[0].action == "auth.login"
        assert logs[0].outcome == "denied"
        assert "invalid credentials" in logs[0].detail

        # Chain must be valid
        ok, broken = verify_chain(org_id)
        assert ok is True
        assert broken is None
