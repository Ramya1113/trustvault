"""
Tests for Access Invalidation (Item 7):
- Confirms a deactivated user's existing session stops working immediately on subsequent requests.
- Confirms a soft-deleted document cannot be reached by ID, download, edit, or sharing URL (returns 404).
"""
from datetime import datetime, timezone
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document
from config import Config


class InvalidationConfig(Config):
    """Configuration for invalidation tests."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Setup app and database for invalidation testing."""
    app = create_app(InvalidationConfig)
    with app.app_context():
        db.create_all()
        org = Organization(name="Invalidation Org")
        db.session.add(org)
        db.session.flush()

        admin = User(org_id=org.id, username="inv_admin", email="admin@inv.org", role="admin")
        admin.set_password("AdminPass123!")

        owner = User(org_id=org.id, username="inv_owner", email="owner@inv.org", role="owner")
        owner.set_password("OwnerPass123!")

        viewer = User(org_id=org.id, username="inv_viewer", email="viewer@inv.org", role="viewer")
        viewer.set_password("ViewerPass123!")

        db.session.add_all([admin, owner, viewer])
        db.session.flush()

        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Confidential Plan",
            filename="confidential.pdf",
            mime_type="application/pdf",
            size=15,
            sha256="dummyhash",
            data=b"%PDF-1.4\nsecret"
        )
        db.session.add(doc)
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()



@pytest.fixture
def client(app):
    return app.test_client()


def test_deactivated_user_session_invalidated_immediately(client, app):
    """
    Verify that if a user is actively signed in and an administrator deactivates them,
    their existing session cookie immediately stops working on the very next request.
    """
    # 1. User signs in successfully
    login_resp = client.post('/auth/login', data={
        'username': 'inv_viewer',
        'password': 'ViewerPass123!'
    }, follow_redirects=False)
    assert login_resp.status_code == 302

    # 2. Confirm they can access dashboard with their active session
    dash_resp = client.get('/auth/dashboard')
    assert dash_resp.status_code == 200

    # 3. Administrator deactivates user in the database
    with app.app_context():
        user = User.query.filter_by(username='inv_viewer').first()
        user.is_active = False
        db.session.commit()

    # 4. On the VERY NEXT request, their session is invalidated and access is denied
    next_resp = client.get('/auth/dashboard', follow_redirects=False)
    assert next_resp.status_code == 302
    assert '/auth/login' in next_resp.headers['Location']


    # Protected documents list also rejects them
    doc_list_resp = client.get('/documents/', follow_redirects=False)
    assert doc_list_resp.status_code == 302
    assert '/auth/login' in doc_list_resp.headers['Location']


def test_soft_deleted_document_unreachable_by_id_download_edit_sharing(client, app):
    """
    Verify that once a document is soft-deleted, it cannot be reached by:
    - Direct view (/documents/<id>) -> 404
    - Download (/documents/<id>/download) -> 404
    - Edit (/documents/<id>/edit) -> 404
    - Sharing management (/documents/<id>/sharing/) -> 404
    """
    # Login as owner
    client.post('/auth/login', data={'username': 'inv_owner', 'password': 'OwnerPass123!'})

    with app.app_context():
        doc = Document.query.filter_by(title="Confidential Plan").first()
        doc_id = doc.id
        # Confirm initially reachable
        assert doc.deleted_at is None

    # Before deletion: document is accessible
    assert client.get(f'/documents/{doc_id}').status_code == 200
    assert client.get(f'/documents/{doc_id}/download').status_code == 200

    # Soft-delete the document
    with app.app_context():
        doc = Document.query.filter_by(id=doc_id).first()
        doc.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()

    # After deletion: all endpoints return 404 Not Found
    resp_view = client.get(f'/documents/{doc_id}')
    assert resp_view.status_code == 404

    resp_download = client.get(f'/documents/{doc_id}/download')
    assert resp_download.status_code == 404

    resp_edit = client.get(f'/documents/{doc_id}/edit')
    assert resp_edit.status_code == 404

    resp_sharing = client.get(f'/documents/{doc_id}/sharing/')
    assert resp_sharing.status_code == 404
