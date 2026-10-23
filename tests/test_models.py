"""
Comprehensive tests for SQLAlchemy models, constraints, and the init-db CLI command.
"""
from datetime import datetime, timezone
import hashlib
import pytest
from sqlalchemy.exc import IntegrityError
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant, AuditLog
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create application and database schema for testing."""
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


def test_organization_and_uniqueness(app):
    """Test Organization creation and unique name constraint."""
    with app.app_context():
        org1 = Organization(name="Acme Corp")
        db.session.add(org1)
        db.session.commit()
        assert org1.id is not None

        # Duplicate name should raise IntegrityError
        org2 = Organization(name="Acme Corp")
        db.session.add(org2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_user_password_and_roles(app):
    """Test User password hashing and role validation."""
    with app.app_context():
        org = Organization(name="Test Org")
        db.session.add(org)
        db.session.commit()

        user = User(
            org_id=org.id,
            username="alice",
            email="alice@example.com",
            role="owner"
        )
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        assert user.check_password("SecurePass123!") is True
        assert user.check_password("WrongPassword") is False
        assert user.role == "owner"
        assert user.is_active is True

        # Duplicate username should fail
        dup_user = User(
            org_id=org.id,
            username="alice",
            email="alice2@example.com",
            role="viewer"
        )
        dup_user.set_password("pass")
        db.session.add(dup_user)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_document_storage_and_soft_delete(app):
    """Test Document binary BLOB storage and soft delete."""
    with app.app_context():
        org = Organization(name="Doc Org")
        db.session.add(org)
        db.session.commit()

        owner = User(
            org_id=org.id,
            username="docowner",
            email="owner@example.com",
            role="owner"
        )
        owner.set_password("secret")
        db.session.add(owner)
        db.session.commit()

        content = b"Confidential document binary bytes"
        content_hash = hashlib.sha256(content).hexdigest()

        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Q4 Financials",
            description="Quarterly financial report",
            filename="financials.pdf",
            mime_type="application/pdf",
            size=len(content),
            sha256=content_hash,
            data=content,
            version=1
        )
        db.session.add(doc)
        db.session.commit()

        assert doc.id is not None
        assert doc.data == content
        assert doc.sha256 == content_hash
        assert doc.is_deleted is False

        # Soft delete
        doc.deleted_at = datetime.now(timezone.utc)
        db.session.commit()
        assert doc.is_deleted is True


def test_access_grant_constraint_one_active_grant(app):
    """Test AccessGrant permissions and one active grant per document+user constraint."""
    with app.app_context():
        org = Organization(name="Grant Org")
        db.session.add(org)
        db.session.commit()

        owner = User(org_id=org.id, username="grant_owner", email="go@example.com", role="owner")
        owner.set_password("pass")
        viewer = User(org_id=org.id, username="grant_viewer", email="gv@example.com", role="viewer")
        viewer.set_password("pass")
        db.session.add_all([owner, viewer])
        db.session.commit()

        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Policy Doc",
            filename="policy.txt",
            size=4,
            sha256="fakehash",
            data=b"test"
        )
        db.session.add(doc)
        db.session.commit()

        # Create active grant
        grant1 = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission="read",
            granted_by=owner.id
        )
        db.session.add(grant1)
        db.session.commit()
        assert grant1.is_active is True

        # Second active grant for the same document and user should violate unique constraint
        grant2 = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission="edit",
            granted_by=owner.id
        )
        db.session.add(grant2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        # Revoking grant1 allows a new active grant to be created
        grant1 = db.session.get(AccessGrant, grant1.id)
        grant1.revoke()
        db.session.commit()
        assert grant1.is_active is False

        # Now creating a new active grant succeeds
        grant3 = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission="edit",
            granted_by=owner.id
        )
        db.session.add(grant3)
        db.session.commit()
        assert grant3.is_active is True


def test_audit_log_hash_chaining(app):
    """Test AuditLog calculation and cryptographic hash chaining."""
    with app.app_context():
        org = Organization(name="Audit Org")
        db.session.add(org)
        db.session.commit()

        # 1. First audit entry (genesis record for this org, prev_hash is None)
        ts1 = datetime.now(timezone.utc).isoformat()
        entry1_hash = AuditLog.calculate_entry_hash(
            prev_hash=None,
            org_id=org.id,
            actor_id=None,
            action="tenant.created",
            target_type="organization",
            target_id=org.id,
            outcome="allowed",
            ip_address="127.0.0.1",
            detail="Organization created",
            created_at_iso=ts1
        )
        log1 = AuditLog(
            org_id=org.id,
            actor_id=None,
            action="tenant.created",
            target_type="organization",
            target_id=org.id,
            outcome="allowed",
            ip_address="127.0.0.1",
            detail="Organization created",
            prev_hash=None,
            entry_hash=entry1_hash
        )
        db.session.add(log1)
        db.session.commit()

        # 2. Second audit entry chained to log1
        ts2 = datetime.now(timezone.utc).isoformat()
        entry2_hash = AuditLog.calculate_entry_hash(
            prev_hash=log1.entry_hash,
            org_id=org.id,
            actor_id=None,
            action="document.view",
            target_type="document",
            target_id=99,
            outcome="denied",
            ip_address="192.168.1.10",
            detail="Unauthorized access attempt",
            created_at_iso=ts2
        )
        log2 = AuditLog(
            org_id=org.id,
            actor_id=None,
            action="document.view",
            target_type="document",
            target_id=99,
            outcome="denied",
            ip_address="192.168.1.10",
            detail="Unauthorized access attempt",
            prev_hash=log1.entry_hash,
            entry_hash=entry2_hash
        )
        db.session.add(log2)
        db.session.commit()

        assert log2.prev_hash == log1.entry_hash
        assert log2.outcome == "denied"


def test_flask_init_db_cli(runner):
    """Test the 'flask init-db' CLI command."""
    result = runner.invoke(args=['init-db'])
    assert result.exit_code == 0
    assert "Initialized database tables successfully." in result.output
