"""
Tests for State-Changing Route POST & CSRF Protection (Item 6):
- Confirms state-changing actions (logout, delete, revoke, toggle-status) reject GET with 405 Method Not Allowed.
- Confirms state-changing actions require CSRF tokens when CSRF is enabled (POST without token yields 400 Bad Request).
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant
from config import Config


class CSRFStateConfig(Config):
    """Configuration with CSRF enabled and testing flag."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = True
    SECRET_KEY = 'csrf-secret-key-for-state-tests'


@pytest.fixture
def app():
    """Setup app with CSRF protection enabled."""
    app = create_app(CSRFStateConfig)
    with app.app_context():
        db.create_all()
        org = Organization(name="State Org")
        db.session.add(org)
        db.session.flush()

        admin = User(org_id=org.id, username="admin_csrf", email="admin@csrf.org", role="admin")
        admin.set_password("AdminPassword123!")

        owner = User(org_id=org.id, username="owner_csrf", email="owner@csrf.org", role="owner")
        owner.set_password("OwnerPassword123!")

        viewer = User(org_id=org.id, username="viewer_csrf", email="viewer@csrf.org", role="viewer")
        viewer.set_password("ViewerPassword123!")

        db.session.add_all([admin, owner, viewer])
        db.session.flush()

        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="State Doc",
            filename="state_doc.pdf",
            mime_type="application/pdf",
            size=10,
            sha256="dummy",
            data=b"%PDF-test"
        )
        db.session.add(doc)
        db.session.flush()

        grant = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission='read',
            granted_by=owner.id
        )
        db.session.add(grant)
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_logout_rejects_get(client):
    """Confirm GET /auth/logout returns 405 Method Not Allowed."""
    response = client.get('/auth/logout')
    assert response.status_code == 405


def test_delete_rejects_get(client, app):
    """Confirm GET /documents/<id>/delete returns 405 Method Not Allowed."""
    with app.app_context():
        doc = Document.query.first()
        doc_id = doc.id
    response = client.get(f'/documents/{doc_id}/delete')
    assert response.status_code == 405


def test_revoke_rejects_get(client, app):
    """Confirm GET /documents/<id>/sharing/<grant_id>/revoke returns 405 Method Not Allowed."""
    with app.app_context():
        doc = Document.query.first()
        grant = AccessGrant.query.first()
        doc_id = doc.id
        grant_id = grant.id
    response = client.get(f'/documents/{doc_id}/sharing/{grant_id}/revoke')
    assert response.status_code == 405


def test_toggle_status_rejects_get(client, app):
    """Confirm GET /admin/users/<id>/toggle-status returns 405 Method Not Allowed."""
    with app.app_context():
        user = User.query.first()
        user_id = user.id
    response = client.get(f'/admin/users/{user_id}/toggle-status')
    assert response.status_code == 405


def test_csrf_required_for_logout(client):
    """Confirm POST /auth/logout without CSRF token returns 400 Bad Request."""
    response = client.post('/auth/logout')
    assert response.status_code == 400


def test_csrf_required_for_delete(client, app):
    """Confirm POST /documents/<id>/delete without CSRF token returns 400 Bad Request."""
    with app.app_context():
        doc = Document.query.first()
        doc_id = doc.id
    response = client.post(f'/documents/{doc_id}/delete')
    assert response.status_code == 400


def test_csrf_required_for_revoke(client, app):
    """Confirm POST /documents/<id>/sharing/<grant_id>/revoke without CSRF token returns 400 Bad Request."""
    with app.app_context():
        doc = Document.query.first()
        grant = AccessGrant.query.first()
        doc_id = doc.id
        grant_id = grant.id
    response = client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke')
    assert response.status_code == 400


def test_csrf_required_for_toggle_status(client, app):
    """Confirm POST /admin/users/<id>/toggle-status without CSRF token returns 400 Bad Request."""
    with app.app_context():
        user = User.query.first()
        user_id = user.id
    response = client.post(f'/admin/users/{user_id}/toggle-status')
    assert response.status_code == 400
