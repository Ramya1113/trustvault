"""
Test for Issue 2: Idempotent seed command and SEED_DEMO=1 automatic execution.
"""
import pytest
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User, Document, AccessGrant


class IdempotentSeedTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(IdempotentSeedTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_flask_seed_is_idempotent(app):
    """
    Verify that calling `flask seed` multiple times:
    - Exits with 0 every time.
    - Does not create duplicate organizations, users, or grants.
    """
    runner = app.test_cli_runner()

    # First run
    res1 = runner.invoke(args=['seed'])
    assert res1.exit_code == 0
    assert "TrustVault: Demo Environment Seeded Successfully!" in res1.output

    # Second run
    res2 = runner.invoke(args=['seed'])
    assert res2.exit_code == 0
    assert "TrustVault: Demo Environment Seeded Successfully!" in res2.output

    with app.app_context():
        # Verify exactly one demo organization exists
        orgs = Organization.query.filter_by(name="Acme Corporation").all()
        assert len(orgs) == 1

        # Verify exactly 3 users exist
        users = User.query.filter_by(org_id=orgs[0].id).all()
        assert len(users) == 3

        # Verify exactly 1 sample document exists
        docs = Document.query.filter_by(title="Welcome to TrustVault Guide").all()
        assert len(docs) == 1

        # Verify exactly 1 grant exists
        grants = AccessGrant.query.filter_by(document_id=docs[0].id, revoked_at=None).all()
        assert len(grants) == 1


def test_seed_demo_env_var_auto_seeds(monkeypatch):
    """
    Verify that setting SEED_DEMO=1 triggers automatic seeding on app creation.
    (Essential for Render free tier where SSH/web shell is unavailable).
    """
    monkeypatch.setenv('SEED_DEMO', '1')

    app = create_app(IdempotentSeedTestConfig)
    with app.app_context():
        # Confirm demo org and users were automatically created
        org = Organization.query.filter_by(name="Acme Corporation").first()
        assert org is not None

        admin = User.query.filter_by(username="demo_admin").first()
        assert admin is not None
        assert admin.role == 'admin'

        owner = User.query.filter_by(username="demo_owner").first()
        assert owner is not None

        viewer = User.query.filter_by(username="demo_viewer").first()
        assert viewer is not None

        doc = Document.query.filter_by(title="Welcome to TrustVault Guide").first()
        assert doc is not None
