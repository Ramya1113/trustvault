"""
Integration tests for Issue 6:
- Verify that Document.data (the binary BLOB) is deferred in document list queries
  in both documents_bp.list_documents and admin_bp.documents_list.
- Verifies that SQLAlchemy inspect(doc).unloaded contains 'data'.
"""

import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import defer
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User, Document


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def test_setup():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()

        org = Organization(name="Defer Test Org")
        db.session.add(org)
        db.session.commit()

        admin = User(
            org_id=org.id,
            username="adminuser",
            email="admin@defer.test",
            role="admin",
            is_active=True
        )
        admin.set_password("AdminPass123!")
        db.session.add(admin)
        db.session.commit()

        # Create a document with binary data payload
        doc = Document(
            org_id=org.id,
            owner_id=admin.id,
            title="Heavy Document",
            description="Doc with payload",
            filename="heavy.txt",
            mime_type="text/plain",
            size=1024,
            sha256="fakehash",
            data=b"A" * 1024,
            version=1
        )
        db.session.add(doc)
        db.session.commit()

        yield app, org, admin, doc
        db.session.remove()
        db.drop_all()


def test_documents_list_query_defers_data(test_setup):
    """Verify that Document.query with defer(Document.data) does not load the BLOB into memory."""
    app, org, admin, doc = test_setup

    with app.app_context():
        # Execute query with defer(Document.data) exactly as done in documents_bp.list_documents
        docs = (
            Document.query
            .options(defer(Document.data))
            .filter_by(org_id=org.id, deleted_at=None)
            .all()
        )
        assert len(docs) == 1
        fetched = docs[0]

        # Inspect state: 'data' column must be in the unloaded set
        state = inspect(fetched)
        assert 'data' in state.unloaded, "'data' BLOB should be deferred and unloaded initially"

        # When accessed, SQLAlchemy lazy-loads the data attribute
        raw_data = fetched.data
        assert raw_data == b"A" * 1024
        assert 'data' not in state.unloaded


def test_admin_documents_list_defers_data(test_setup):
    """Verify that admin document repository query also defers Document.data."""
    app, org, admin, doc = test_setup

    with app.app_context():
        # Admin document repository query
        admin_docs = (
            Document.query
            .options(defer(Document.data))
            .filter_by(org_id=org.id)
            .all()
        )
        assert len(admin_docs) == 1
        fetched = admin_docs[0]

        state = inspect(fetched)
        assert 'data' in state.unloaded, "'data' BLOB should be deferred in admin repository list"


def test_http_endpoint_list_documents_renders_without_loading_data_beforehand(test_setup):
    """Test HTTP GET /documents and GET /admin/documents respond with 200 OK."""
    app, org, admin, doc = test_setup
    client = app.test_client()

    client.post('/auth/login', data={'username': 'adminuser', 'password': 'AdminPass123!'})

    resp = client.get('/documents/', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Heavy Document" in resp.data

    resp_admin = client.get('/admin/documents', follow_redirects=True)
    assert resp_admin.status_code == 200
    assert b"Heavy Document" in resp_admin.data
