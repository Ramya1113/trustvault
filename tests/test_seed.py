"""
Tests for database initialization, seed commands, and Render configuration.
"""
from app import create_app
from config import Config, get_database_uri
from app.models import Organization, User, Document, AccessGrant, AuditLog
from app.audit import verify_chain


def test_database_url_postgres_dialect_fix(monkeypatch):
    """Verify postgres:// is transparently replaced with postgresql://."""
    monkeypatch.setenv('DATABASE_URL', 'postgres://user:pass@host:5432/dbname')
    uri = get_database_uri()
    assert uri == 'postgresql://user:pass@host:5432/dbname'

    # When created via app factory, SQLALCHEMY_DATABASE_URI also has dialect fixed
    app = create_app()
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://user:pass@host:5432/dbname'


def test_secret_key_environment_variable(monkeypatch):
    """Verify SECRET_KEY is read from environment variable."""
    monkeypatch.setenv('SECRET_KEY', 'custom-render-production-secret-key-999')
    app = create_app()
    assert app.config['SECRET_KEY'] == 'custom-render-production-secret-key-999'


import pytest
from extensions import db


class SeedTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(SeedTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_flask_seed_cli_command(app):
    """Verify flask seed command populates demo organization, users, and valid audit chain."""
    runner = app.test_cli_runner()
    result = runner.invoke(args=['seed'])
    assert result.exit_code == 0
    assert "TrustVault: Demo Environment Seeded Successfully!" in result.output
    assert "demo_admin" in result.output
    assert "demo_owner" in result.output
    assert "demo_viewer" in result.output

    with app.app_context():
        # Verify org
        org = Organization.query.filter_by(name="Acme Corporation").first()
        assert org is not None

        # Verify users
        admin = User.query.filter_by(username="demo_admin").first()
        owner = User.query.filter_by(username="demo_owner").first()
        viewer = User.query.filter_by(username="demo_viewer").first()

        assert admin is not None and admin.role == 'admin' and admin.check_password("AdminPassword123!")
        assert owner is not None and owner.role == 'owner' and owner.check_password("OwnerPassword123!")
        assert viewer is not None and viewer.role == 'viewer' and viewer.check_password("ViewerPassword123!")

        # Verify sample document
        doc = Document.query.filter_by(title="Welcome to TrustVault Guide").first()
        assert doc is not None
        assert doc.owner_id == owner.id

        # Verify grant
        grant = AccessGrant.query.filter_by(document_id=doc.id, user_id=viewer.id).first()
        assert grant is not None
        assert grant.permission == 'read'

        # Verify audit chain integrity
        is_valid, broken_id = verify_chain(org.id)
        assert is_valid is True
        assert broken_id is None
