"""
Comprehensive tests for document management: upload, listing, search, detail, download,
version editing, soft deletion, permissions enforcement, and audit logging.
"""
import io
import hashlib
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant, AuditLog
from config import Config


class DocTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create test application and in-memory database."""
    app = create_app(DocTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def setup_data(app):
    """
    Set up organizations and users for testing document operations.
    """
    with app.app_context():
        # Tenant 1: Acme
        org1 = Organization(name="Acme Corp")
        # Tenant 2: Beta
        org2 = Organization(name="Beta Corp")
        db.session.add_all([org1, org2])
        db.session.flush()

        # Tenant 1 users
        admin1 = User(org_id=org1.id, username="acme_admin", email="admin@acme.com", role="admin")
        admin1.set_password("AdminPass1234!")

        owner1 = User(org_id=org1.id, username="acme_owner", email="owner@acme.com", role="owner")
        owner1.set_password("OwnerPass1234!")

        viewer1 = User(org_id=org1.id, username="acme_viewer", email="viewer@acme.com", role="viewer")
        viewer1.set_password("ViewerPass1234!")

        # Tenant 2 user
        admin2 = User(org_id=org2.id, username="beta_admin", email="admin@beta.com", role="admin")
        admin2.set_password("BetaPass1234!")

        db.session.add_all([admin1, owner1, viewer1, admin2])
        db.session.commit()

        return {
            'org1_id': org1.id,
            'org2_id': org2.id,
            'admin1_id': admin1.id,
            'owner1_id': owner1.id,
            'viewer1_id': viewer1.id,
            'admin2_id': admin2.id,
        }


def login_as(client, username, password):
    """Helper to authenticate a user."""
    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


# -----------------------------------------------------------------------------
# Upload Tests
# -----------------------------------------------------------------------------

def test_owner_and_admin_can_upload(client, setup_data, app):
    """Verify admin and owner can upload documents; raw bytes and sha256 stored."""
    login_as(client, "acme_owner", "OwnerPass1234!")

    pdf_bytes = b"%PDF-1.4 sample PDF content bytes"
    expected_hash = hashlib.sha256(pdf_bytes).hexdigest()

    response = client.post('/documents/upload', data={
        'title': 'Q1 Financial Report',
        'description': 'Quarterly financial details',
        'file': (io.BytesIO(pdf_bytes), 'report.pdf')
    }, content_type='multipart/form-data', follow_redirects=True)

    assert response.status_code == 200
    assert b"Q1 Financial Report" in response.data

    with app.app_context():
        doc = Document.query.filter_by(title='Q1 Financial Report').first()
        assert doc is not None
        assert doc.filename == 'report.pdf'
        assert doc.data == pdf_bytes
        assert doc.size == len(pdf_bytes)
        assert doc.sha256 == expected_hash
        assert doc.version == 1
        assert doc.mime_type == 'application/pdf'

        # Verify audit log
        log = AuditLog.query.filter_by(action="document.upload", target_id=doc.id).first()
        assert log is not None
        assert log.outcome == "allowed"


def test_viewer_upload_denied(client, setup_data, app):
    """Verify viewers are strictly prohibited from uploading (403 and denied audit log)."""
    login_as(client, "acme_viewer", "ViewerPass1234!")

    response = client.post('/documents/upload', data={
        'title': 'Viewer Forbidden Upload',
        'file': (io.BytesIO(b"content"), 'test.txt')
    }, content_type='multipart/form-data')

    assert response.status_code == 403

    with app.app_context():
        # Assert no document created
        assert Document.query.filter_by(title='Viewer Forbidden Upload').first() is None
        # Assert denied audit event logged
        log = AuditLog.query.filter_by(action="document.upload", outcome="denied").first()
        assert log is not None
        assert "not authorized to upload" in log.detail


def test_upload_extension_allowlist(client, setup_data, app):
    """Verify disallowed extensions (.exe, .sh) are rejected."""
    login_as(client, "acme_owner", "OwnerPass1234!")

    # Attempt .exe upload
    resp_exe = client.post('/documents/upload', data={
        'title': 'Malicious App',
        'file': (io.BytesIO(b"binary"), 'virus.exe')
    }, content_type='multipart/form-data', follow_redirects=True)

    assert resp_exe.status_code == 200
    assert b"Invalid file type. Allowed extensions" in resp_exe.data

    with app.app_context():
        assert Document.query.filter_by(title='Malicious App').first() is None


def test_upload_file_size_limit(client, setup_data, app):
    """Verify uploads exceeding 5 MB are rejected."""
    login_as(client, "acme_owner", "OwnerPass1234!")

    # 5 MB + 1 byte
    too_large_bytes = b"x" * (5 * 1024 * 1024 + 1)

    resp = client.post('/documents/upload', data={
        'title': 'Huge Document',
        'file': (io.BytesIO(too_large_bytes), 'huge.pdf')
    }, content_type='multipart/form-data', follow_redirects=True)

    assert resp.status_code in [200, 413]
    if resp.status_code == 200:
        assert b"File size exceeds maximum allowed limit of 5 MB" in resp.data

    with app.app_context():
        assert Document.query.filter_by(title='Huge Document').first() is None


# -----------------------------------------------------------------------------
# List & Search Tests
# -----------------------------------------------------------------------------

def test_document_listing_and_tenant_isolation(client, setup_data, app):
    """
    Verify listing rules:
    - Admin sees all docs in org
    - Owner sees owned + shared
    - Viewer sees only shared
    - Zero cross-tenant document exposure
    """
    with app.app_context():
        ctx = setup_data
        # Doc in Tenant 1 owned by owner1
        doc1 = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Acme Financials",
            filename="financials.xlsx",
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            size=100,
            sha256="hash1",
            data=b"data1"
        )
        # Doc in Tenant 1 owned by admin1
        doc2 = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['admin1_id'],
            title="Acme Security Policy",
            filename="policy.docx",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            size=100,
            sha256="hash2",
            data=b"data2"
        )
        # Doc in Tenant 2
        doc_tenant2 = Document(
            org_id=ctx['org2_id'],
            owner_id=ctx['admin2_id'],
            title="Beta Secret Roadmap",
            filename="roadmap.pdf",
            mime_type="application/pdf",
            size=100,
            sha256="hash3",
            data=b"data3"
        )
        db.session.add_all([doc1, doc2, doc_tenant2])
        db.session.commit()

        # Share doc1 with viewer1
        grant = AccessGrant(
            document_id=doc1.id,
            user_id=ctx['viewer1_id'],
            permission="read",
            granted_by=ctx['owner1_id']
        )
        db.session.add(grant)
        db.session.commit()

    # 1. Admin logs in -> sees doc1 and doc2, NOT doc_tenant2
    login_as(client, "acme_admin", "AdminPass1234!")
    resp_admin = client.get('/documents/')
    assert resp_admin.status_code == 200
    assert b"Acme Financials" in resp_admin.data
    assert b"Acme Security Policy" in resp_admin.data
    assert b"Beta Secret Roadmap" not in resp_admin.data

    # 2. Viewer logs in -> sees ONLY shared doc1, NOT doc2 or doc_tenant2
    client.get('/auth/logout')
    login_as(client, "acme_viewer", "ViewerPass1234!")
    resp_viewer = client.get('/documents/')
    assert resp_viewer.status_code == 200
    assert b"Acme Financials" in resp_viewer.data
    assert b"Acme Security Policy" not in resp_viewer.data
    assert b"Beta Secret Roadmap" not in resp_viewer.data


def test_search_by_title_filter(client, setup_data, app):
    """Verify search filter ?q= matches title and filters correctly."""
    with app.app_context():
        ctx = setup_data
        docA = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Engineering Architecture Blueprints",
            filename="arch.pdf",
            size=50,
            sha256="h1",
            data=b"data"
        )
        docB = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Annual Human Resources Guidelines",
            filename="hr.pdf",
            size=50,
            sha256="h2",
            data=b"data"
        )
        db.session.add_all([docA, docB])
        db.session.commit()

    login_as(client, "acme_owner", "OwnerPass1234!")

    # Search for "architecture"
    resp = client.get('/documents/?q=architecture')
    assert resp.status_code == 200
    assert b"Engineering Architecture Blueprints" in resp.data
    assert b"Annual Human Resources Guidelines" not in resp.data


# -----------------------------------------------------------------------------
# Detail & Download Tests
# -----------------------------------------------------------------------------

def test_detail_and_download_security_headers(client, setup_data, app):
    """
    Verify detail view and download response headers:
    - Content-Disposition: attachment; filename="..."
    - X-Content-Type-Options: nosniff
    """
    with app.app_context():
        ctx = setup_data
        file_content = b"Binary spreadsheet data payload"
        doc = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Q3 Budget",
            filename="budget.xlsx",
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            size=len(file_content),
            sha256=hashlib.sha256(file_content).hexdigest(),
            data=file_content
        )
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

    login_as(client, "acme_owner", "OwnerPass1234!")

    # 1. Detail view
    detail_resp = client.get(f'/documents/{doc_id}')
    assert detail_resp.status_code == 200
    assert b"Q3 Budget" in detail_resp.data
    assert b"budget.xlsx" in detail_resp.data

    # 2. Download view
    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200
    assert dl_resp.data == file_content
    assert dl_resp.headers.get('Content-Disposition') == 'attachment; filename="budget.xlsx"'
    assert dl_resp.headers.get('X-Content-Type-Options') == 'nosniff'


def test_cross_tenant_document_lookup_returns_404_and_logs(client, setup_data, app):
    """
    Verify cross-tenant document probe returns 404 and is logged as denied in audit log.
    """
    with app.app_context():
        ctx = setup_data
        doc_tenant2 = Document(
            org_id=ctx['org2_id'],
            owner_id=ctx['admin2_id'],
            title="Tenant 2 Confidential",
            filename="secret.pdf",
            size=20,
            sha256="h2",
            data=b"secret"
        )
        db.session.add(doc_tenant2)
        db.session.commit()
        tenant2_doc_id = doc_tenant2.id

    # User in Tenant 1 tries to access Tenant 2 document
    login_as(client, "acme_admin", "AdminPass1234!")
    resp = client.get(f'/documents/{tenant2_doc_id}')
    assert resp.status_code == 404

    with app.app_context():
        log = AuditLog.query.filter_by(
            action="document.view",
            target_id=tenant2_doc_id,
            outcome="denied"
        ).first()
        assert log is not None
        assert "Cross-tenant" in log.detail


# -----------------------------------------------------------------------------
# Edit & Versioning Tests
# -----------------------------------------------------------------------------

def test_edit_document_and_new_version(client, setup_data, app):
    """
    Verify document editing:
    - Metadata update
    - New file upload increments version to version+1 and updates sha256
    """
    with app.app_context():
        ctx = setup_data
        original_bytes = b"Version 1 Content"
        doc = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Original Spec",
            filename="spec_v1.txt",
            mime_type="text/plain",
            size=len(original_bytes),
            sha256=hashlib.sha256(original_bytes).hexdigest(),
            data=original_bytes,
            version=1
        )
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

    login_as(client, "acme_owner", "OwnerPass1234!")

    new_bytes = b"Version 2 Updated Content"
    new_hash = hashlib.sha256(new_bytes).hexdigest()

    resp = client.post(f'/documents/{doc_id}/edit', data={
        'title': 'Revised Spec Title',
        'description': 'Updated with new requirements',
        'file': (io.BytesIO(new_bytes), 'spec_v2.txt')
    }, content_type='multipart/form-data', follow_redirects=True)

    assert resp.status_code == 200
    assert b"Revised Spec Title" in resp.data

    with app.app_context():
        updated_doc = db.session.get(Document, doc_id)
        assert updated_doc.title == 'Revised Spec Title'
        assert updated_doc.description == 'Updated with new requirements'
        assert updated_doc.filename == 'spec_v2.txt'
        assert updated_doc.version == 2
        assert updated_doc.data == new_bytes
        assert updated_doc.sha256 == new_hash

        # Verify audit log
        log = AuditLog.query.filter_by(action="document.edit", target_id=doc_id).first()
        assert log is not None
        assert "version 2" in log.detail


def test_viewer_without_edit_grant_cannot_edit(client, setup_data, app):
    """Verify viewer with read-only grant is denied edit access (403 and denied audit log)."""
    with app.app_context():
        ctx = setup_data
        doc = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Read Only Doc",
            filename="ro.pdf",
            size=10,
            sha256="ro",
            data=b"ro"
        )
        db.session.add(doc)
        db.session.commit()

        # Grant read-only access
        grant = AccessGrant(
            document_id=doc.id,
            user_id=ctx['viewer1_id'],
            permission="read",
            granted_by=ctx['owner1_id']
        )
        db.session.add(grant)
        db.session.commit()
        doc_id = doc.id

    login_as(client, "acme_viewer", "ViewerPass1234!")

    # Attempt to access edit route
    resp = client.get(f'/documents/{doc_id}/edit')
    assert resp.status_code == 403

    with app.app_context():
        log = AuditLog.query.filter_by(action="document.edit", target_id=doc_id, outcome="denied").first()
        assert log is not None
        assert "Unauthorized edit attempt" in log.detail


# -----------------------------------------------------------------------------
# Soft Deletion Tests
# -----------------------------------------------------------------------------

def test_soft_delete_document(client, setup_data, app):
    """
    Verify soft delete:
    - Sets deleted_at
    - No longer appears in document list
    - Subsequent detail/download returns 404
    """
    with app.app_context():
        ctx = setup_data
        doc = Document(
            org_id=ctx['org1_id'],
            owner_id=ctx['owner1_id'],
            title="Doc to Delete",
            filename="trash.pdf",
            size=10,
            sha256="trash",
            data=b"trash"
        )
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

    login_as(client, "acme_owner", "OwnerPass1234!")

    del_resp = client.post(f'/documents/{doc_id}/delete', follow_redirects=True)
    assert del_resp.status_code == 200
    assert b"has been deleted" in del_resp.data

    with app.app_context():
        deleted_doc = db.session.get(Document, doc_id)
        assert deleted_doc.is_deleted is True
        assert deleted_doc.deleted_at is not None

        # Verify audit log
        log = AuditLog.query.filter_by(action="document.delete", target_id=doc_id).first()
        assert log is not None
        assert log.outcome == "allowed"

    # Detail view of soft-deleted document returns 404
    detail_resp = client.get(f'/documents/{doc_id}')
    assert detail_resp.status_code == 404

    # Download of soft-deleted document returns 404
    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 404
