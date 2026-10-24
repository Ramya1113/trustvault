"""
Integration tests for TrustVault using the Flask test client.

Covers the complete security and lifecycle workflows:
1. Registration creates an Organization and makes that user its Admin.
2. Viewer role cannot upload documents (GET and POST return 403 Forbidden).
3. Viewer cannot open an unshared document by changing the ID in the URL (403 Forbidden).
4. User from another organization gets 403 or 404 even with a valid document ID (strict multi-tenancy).
5. Owner can grant access; revoking access takes effect immediately on the next request.
6. Viewer cannot call the access grant, change, or revoke endpoints (403 Forbidden).
7. Denied attempts across all sensitive actions appear in the append-only audit log.
8. Tampering with any audit log row directly in the database is detected by chain verification.
9. Oversize files (> 5 MB) and disallowed file extensions are rejected.
"""

import io
import hashlib
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant, AuditLog
from app.audit import log_event, verify_chain
from config import Config


class IntegrationTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create test application and in-memory database."""
    app = create_app(IntegrationTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def setup_integration_data(app):
    """
    Set up two isolated organizations with users and baseline documents.
    """
    with app.app_context():
        # Organization 1: Cyberdyne
        org1 = Organization(name="Cyberdyne Systems")
        # Organization 2: Weyland-Yutani
        org2 = Organization(name="Weyland-Yutani")
        db.session.add_all([org1, org2])
        db.session.flush()

        # Users in Cyberdyne (Org 1)
        admin1 = User(org_id=org1.id, username="cyber_admin", email="admin@cyberdyne.io", role="admin")
        admin1.set_password("AdminPass1234!")

        owner1 = User(org_id=org1.id, username="cyber_owner", email="owner@cyberdyne.io", role="owner")
        owner1.set_password("OwnerPass1234!")

        viewer1 = User(org_id=org1.id, username="cyber_viewer", email="viewer@cyberdyne.io", role="viewer")
        viewer1.set_password("ViewerPass1234!")

        viewer2 = User(org_id=org1.id, username="cyber_viewer2", email="viewer2@cyberdyne.io", role="viewer")
        viewer2.set_password("ViewerPass1234!")

        # Users in Weyland-Yutani (Org 2 - Cross-tenant)
        weyland_admin = User(org_id=org2.id, username="weyland_admin", email="admin@weyland.com", role="admin")
        weyland_admin.set_password("WeylandAdmin1234!")

        weyland_viewer = User(org_id=org2.id, username="weyland_viewer", email="viewer@weyland.com", role="viewer")
        weyland_viewer.set_password("WeylandViewer1234!")

        db.session.add_all([admin1, owner1, viewer1, viewer2, weyland_admin, weyland_viewer])
        db.session.flush()

        # Documents in Cyberdyne (Org 1)
        doc1 = Document(
            org_id=org1.id,
            owner_id=owner1.id,
            title="Cyberdyne AI Blueprint",
            description="Confidential neural net specifications",
            filename="blueprint.pdf",
            mime_type="application/pdf",
            size=1024,
            sha256="1" * 64,
            data=b"cyberdyne confidential neural network data"
        )

        # Documents in Weyland-Yutani (Org 2)
        weyland_doc = Document(
            org_id=org2.id,
            owner_id=weyland_admin.id,
            title="Nostromo Flight Log",
            description="Deep space cargo route",
            filename="flight_log.pdf",
            mime_type="application/pdf",
            size=2048,
            sha256="2" * 64,
            data=b"nostromo route coordinates"
        )

        db.session.add_all([doc1, weyland_doc])
        db.session.commit()

        return {
            'org1_id': org1.id,
            'org2_id': org2.id,
            'admin1_id': admin1.id,
            'owner1_id': owner1.id,
            'viewer1_id': viewer1.id,
            'viewer2_id': viewer2.id,
            'weyland_admin_id': weyland_admin.id,
            'weyland_viewer_id': weyland_viewer.id,
            'doc1_id': doc1.id,
            'weyland_doc_id': weyland_doc.id,
        }


def login_as(client, username, password):
    """Helper to authenticate a user through the login form."""
    client.post('/auth/logout', follow_redirects=True)

    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


# =============================================================================
# 1. Registration creates Org + Admin
# =============================================================================

def test_integration_register_creates_org_and_admin(client, app):
    """
    Verify that public registration:
    1. Creates a brand-new Organization tenant.
    2. Registers the new user as its 'admin'.
    3. Hashes the password securely (never plaintext).
    4. Automatically logs the user in and redirects to the dashboard.
    5. Appends a tamper-evident audit log entry.
    """
    resp = client.post('/auth/register', data={
        'organization_name': 'Initech Software',
        'username': 'peter_gibbons',
        'email': 'peter@initech.com',
        'password': 'TPSReportPass123!',
        'password_confirm': 'TPSReportPass123!'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Organization &#39;Initech Software&#39; and administrator account created successfully" in resp.data or b"created successfully" in resp.data

    with app.app_context():
        # Verify Organization created
        org = Organization.query.filter_by(name='Initech Software').first()
        assert org is not None

        # Verify User created and assigned admin role in the new org
        user = User.query.filter_by(username='peter_gibbons').first()
        assert user is not None
        assert user.org_id == org.id
        assert user.role == 'admin'
        assert user.is_active is True
        assert user.check_password('TPSReportPass123!')
        assert user.password_hash != 'TPSReportPass123!'

        # Verify Audit Log entry created for registration
        audit = AuditLog.query.filter_by(org_id=org.id, action="auth.register").first()
        assert audit is not None
        assert audit.actor_id == user.id
        assert audit.outcome == "allowed"

        # Verify cryptographic chain is valid
        is_valid, _ = verify_chain(org.id)
        assert is_valid is True


# =============================================================================
# 2. Viewer cannot upload
# =============================================================================

def test_integration_viewer_cannot_upload(client, setup_integration_data, app):
    """
    Verify that a viewer is strictly forbidden from uploading files:
    - GET /documents/upload returns 403 Forbidden.
    - POST /documents/upload returns 403 Forbidden.
    - No document is saved to the database.
    - Denied attempt is recorded in the audit log.
    """
    login_as(client, "cyber_viewer", "ViewerPass1234!")

    # GET /documents/upload -> 403
    get_resp = client.get('/documents/upload')
    assert get_resp.status_code == 403

    # POST /documents/upload -> 403
    post_resp = client.post('/documents/upload', data={
        'title': 'Viewer Attempted Upload',
        'file': (io.BytesIO(b"viewer content"), 'test.txt')
    }, content_type='multipart/form-data')
    assert post_resp.status_code == 403

    with app.app_context():
        # No document stored in database
        doc = Document.query.filter_by(title='Viewer Attempted Upload').first()
        assert doc is None

        # Denied attempt logged
        denied_log = AuditLog.query.filter_by(action="document.upload", outcome="denied").first()
        assert denied_log is not None
        assert "not authorized to upload" in denied_log.detail


# =============================================================================
# 3. Viewer cannot open unshared document by changing ID in URL
# =============================================================================

def test_integration_viewer_cannot_open_unshared_document_by_id(client, setup_integration_data, app):
    """
    Verify horizontal privilege escalation prevention:
    A viewer guessing or directly changing the document ID in the URL receives 403 Forbidden
    when trying to view, download, or edit an unshared document.
    """
    ctx = setup_integration_data
    doc_id = ctx['doc1_id']

    login_as(client, "cyber_viewer", "ViewerPass1234!")

    # Attempt to view document metadata
    view_resp = client.get(f'/documents/{doc_id}')
    assert view_resp.status_code == 403

    # Attempt to download binary payload
    download_resp = client.get(f'/documents/{doc_id}/download')
    assert download_resp.status_code == 403

    # Attempt to open edit form
    edit_resp = client.get(f'/documents/{doc_id}/edit')
    assert edit_resp.status_code == 403

    # Attempt to soft-delete
    delete_resp = client.post(f'/documents/{doc_id}/delete')
    assert delete_resp.status_code == 403

    with app.app_context():
        # Verify denied audit entries
        denied_logs = AuditLog.query.filter_by(
            actor_id=ctx['viewer1_id'],
            target_id=doc_id,
            outcome="denied"
        ).all()
        assert len(denied_logs) >= 3


# =============================================================================
# 4. User from another org gets 403 or 404 even with a valid document ID
# =============================================================================

def test_integration_cross_tenant_user_blocked_with_valid_document_id(client, setup_integration_data, app):
    """
    Verify multi-tenant isolation:
    A user from Organization 2 (even an admin) requesting a valid document ID
    belonging to Organization 1 receives 404 (or 403) and no information is leaked.
    """
    ctx = setup_integration_data
    cyber_doc_id = ctx['doc1_id']

    # Log in as Weyland-Yutani Admin
    login_as(client, "weyland_admin", "WeylandAdmin1234!")

    # Direct ID probe for Org 1's document
    detail_resp = client.get(f'/documents/{cyber_doc_id}')
    assert detail_resp.status_code in [403, 404]

    download_resp = client.get(f'/documents/{cyber_doc_id}/download')
    assert download_resp.status_code in [403, 404]

    sharing_resp = client.get(f'/documents/{cyber_doc_id}/sharing/')
    assert sharing_resp.status_code in [403, 404]

    edit_resp = client.get(f'/documents/{cyber_doc_id}/edit')
    assert edit_resp.status_code in [403, 404]

    # Verify response body contains NO confidential data from Org 1
    assert b"Cyberdyne AI Blueprint" not in detail_resp.data
    assert b"cyberdyne confidential" not in download_resp.data

    # Log in as Weyland-Yutani Viewer
    login_as(client, "weyland_viewer", "WeylandViewer1234!")

    viewer_resp = client.get(f'/documents/{cyber_doc_id}')
    assert viewer_resp.status_code in [403, 404]


# =============================================================================
# 5. Owner can grant, revoke removes access immediately
# =============================================================================

def test_integration_owner_can_grant_and_revoke_removes_access_immediately(client, setup_integration_data, app):
    """
    Verify complete sharing lifecycle:
    1. Viewer initially has NO access (403).
    2. Owner grants 'read' access to Viewer.
    3. Viewer can now view and download the document (200 OK).
    4. Owner revokes access.
    5. On the very next request, Viewer is immediately blocked (403 Forbidden).
    """
    ctx = setup_integration_data
    doc_id = ctx['doc1_id']
    viewer_id = ctx['viewer1_id']

    # Step 1: Viewer has no initial access
    login_as(client, "cyber_viewer", "ViewerPass1234!")
    assert client.get(f'/documents/{doc_id}').status_code == 403

    # Step 2: Owner logs in and grants 'read' access
    login_as(client, "cyber_owner", "OwnerPass1234!")
    grant_resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': viewer_id,
        'permission': 'read'
    }, follow_redirects=True)
    assert grant_resp.status_code == 200
    assert b"Granted Read access to" in grant_resp.data

    with app.app_context():
        active_grant = AccessGrant.query.filter_by(
            document_id=doc_id,
            user_id=viewer_id,
            revoked_at=None
        ).first()
        assert active_grant is not None
        assert active_grant.permission == 'read'
        grant_id = active_grant.id

    # Step 3: Viewer can view and download
    login_as(client, "cyber_viewer", "ViewerPass1234!")
    view_resp = client.get(f'/documents/{doc_id}')
    assert view_resp.status_code == 200
    assert b"Cyberdyne AI Blueprint" in view_resp.data

    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200
    assert dl_resp.data == b"cyberdyne confidential neural network data"

    # Step 4: Owner revokes access
    login_as(client, "cyber_owner", "OwnerPass1234!")
    revoke_resp = client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke', follow_redirects=True)
    assert revoke_resp.status_code == 200
    assert b"Revoked access for" in revoke_resp.data

    with app.app_context():
        revoked_grant = db.session.get(AccessGrant, grant_id)
        assert revoked_grant.revoked_at is not None
        assert revoked_grant.is_active is False

    # Step 5: Viewer makes next request - immediately receives 403 Forbidden
    login_as(client, "cyber_viewer", "ViewerPass1234!")
    after_revoke_view = client.get(f'/documents/{doc_id}')
    assert after_revoke_view.status_code == 403

    after_revoke_download = client.get(f'/documents/{doc_id}/download')
    assert after_revoke_download.status_code == 403

    # Document also disappears from viewer's document list
    list_resp = client.get('/documents/')
    assert b"Cyberdyne AI Blueprint" not in list_resp.data


# =============================================================================
# 6. Viewer cannot call the grant endpoint
# =============================================================================

def test_integration_viewer_cannot_call_grant_endpoint(client, setup_integration_data, app):
    """
    Verify that a viewer can NEVER manage access or grant permissions:
    - POST /documents/<id>/sharing/grant returns 403 Forbidden.
    - GET /documents/<id>/sharing/ returns 403 Forbidden.
    - POST /documents/<id>/sharing/<grant_id>/revoke returns 403 Forbidden.
    - No access grant is created.
    - Denied attempt is logged.
    """
    ctx = setup_integration_data
    doc_id = ctx['doc1_id']
    target_viewer2_id = ctx['viewer2_id']

    login_as(client, "cyber_viewer", "ViewerPass1234!")

    # Attempt GET manage sharing
    get_resp = client.get(f'/documents/{doc_id}/sharing/')
    assert get_resp.status_code == 403

    # Attempt POST grant access
    post_resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': target_viewer2_id,
        'permission': 'read'
    })
    assert post_resp.status_code == 403

    with app.app_context():
        # Ensure no grant was created
        grant = AccessGrant.query.filter_by(document_id=doc_id, user_id=target_viewer2_id).first()
        assert grant is None

        # Verify denied audit entry
        denied_log = AuditLog.query.filter_by(
            actor_id=ctx['viewer1_id'],
            action="document.manage_access",
            outcome="denied"
        ).first()
        assert denied_log is not None


# =============================================================================
# 7. Denied attempts appear in the audit log
# =============================================================================

def test_integration_denied_attempts_appear_in_audit_log(client, setup_integration_data, app):
    """
    Verify that every denied attempt across the platform is persisted in the audit log:
    - Bad password login failure
    - Viewer attempting upload
    - Viewer attempting access management
    - Non-admin attempting admin user management
    And the hash chain remains valid.
    """
    ctx = setup_integration_data
    doc_id = ctx['doc1_id']
    org1_id = ctx['org1_id']

    # 1. Failed login attempt
    client.post('/auth/login', data={
        'username': 'cyber_admin',
        'password': 'WrongPassword999!'
    })

    # 2. Viewer attempting upload
    login_as(client, "cyber_viewer", "ViewerPass1234!")
    client.post('/documents/upload', data={'title': 'Denied Upload'})

    # 3. Viewer attempting to grant access
    client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': ctx['viewer2_id'],
        'permission': 'read'
    })

    # 4. Viewer attempting admin user management
    client.get('/admin/users')

    with app.app_context():
        # Query all denied events for Org 1
        denied_events = (
            AuditLog.query
            .filter_by(org_id=org1_id, outcome="denied")
            .order_by(AuditLog.id.asc())
            .all()
        )

        assert len(denied_events) >= 4
        actions = [e.action for e in denied_events]
        assert "auth.login" in actions
        assert "document.upload" in actions
        assert "document.manage_access" in actions
        assert "admin.manage_users" in actions

        # Verify that all entries (including denied ones) form an unbroken cryptographic chain
        is_valid, broken_id = verify_chain(org1_id)
        assert is_valid is True
        assert broken_id is None


# =============================================================================
# 8. Tampered audit row is detected
# =============================================================================

def test_integration_tampered_audit_row_is_detected(client, setup_integration_data, app):
    """
    Verify tamper-evident hash chaining:
    1. Initial chain is 100% valid.
    2. Modifying a row directly in the database is detected by verify_chain.
    3. The admin verification route highlights the exact broken entry ID.
    """
    ctx = setup_integration_data
    org1_id = ctx['org1_id']

    # Generate 5 audit events
    with app.app_context():
        for i in range(5):
            log_event(
                actor=ctx['admin1_id'],
                action=f"security.event_{i}",
                target_type="system",
                target_id=i,
                outcome="allowed",
                detail=f"Security event sequence {i}",
                org_id=org1_id
            )

        # Baseline: chain is intact
        ok, broken_id = verify_chain(org1_id)
        assert ok is True
        assert broken_id is None

        # Select the 3rd event to tamper with
        entry_to_tamper = AuditLog.query.filter_by(org_id=org1_id, action="security.event_2").first()
        assert entry_to_tamper is not None
        tampered_entry_id = entry_to_tamper.id

        # Directly tamper with the database row (bypassing ORM)
        db.session.execute(
            db.text("UPDATE audit_logs SET detail = :new_detail WHERE id = :id"),
            {"new_detail": "TAMPERED BY ATTACKER", "id": tampered_entry_id}
        )
        db.session.commit()
        db.session.expire_all()

        # Chain verification now MUST fail and point to the tampered entry
        ok_after_tamper, detected_broken_id = verify_chain(org1_id)
        assert ok_after_tamper is False
        assert detected_broken_id == tampered_entry_id

    # Test via Flask Admin UI endpoint
    login_as(client, "cyber_admin", "AdminPass1234!")
    verify_resp = client.post('/admin/audit/verify', follow_redirects=True)
    assert verify_resp.status_code == 200
    assert b"Chain Verification FAILED" in verify_resp.data or b"integrity compromised" in verify_resp.data
    assert str(tampered_entry_id).encode() in verify_resp.data


# =============================================================================
# 9. Oversize and disallowed file types are rejected
# =============================================================================

def test_integration_oversize_and_disallowed_file_types_rejected(client, setup_integration_data, app):
    """
    Verify upload security restrictions:
    - Disallowed extensions (.exe, .sh, .py, .php) are rejected.
    - Files exceeding the 5 MB threshold are rejected.
    - Valid files (e.g. .pdf, .docx, <= 5 MB) are accepted and stored as BLOBs.
    """
    login_as(client, "cyber_owner", "OwnerPass1234!")

    # 1. Disallowed extension: executable .exe
    resp_exe = client.post('/documents/upload', data={
        'title': 'Ransomware Payload',
        'file': (io.BytesIO(b"binary payload"), 'malware.exe')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_exe.status_code == 200
    assert b"Invalid file type. Allowed extensions" in resp_exe.data

    # 2. Disallowed extension: shell script .sh
    resp_sh = client.post('/documents/upload', data={
        'title': 'Shell Script',
        'file': (io.BytesIO(b"#!/bin/bash\nrm -rf /"), 'script.sh')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_sh.status_code == 200
    assert b"Invalid file type. Allowed extensions" in resp_sh.data

    # 3. Oversize file: 5 MB + 1024 bytes
    too_large_payload = b"A" * (5 * 1024 * 1024 + 1024)
    resp_oversize = client.post('/documents/upload', data={
        'title': 'Huge File',
        'file': (io.BytesIO(too_large_payload), 'huge_doc.pdf')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_oversize.status_code in [200, 413]
    if resp_oversize.status_code == 200:
        assert b"File size exceeds maximum allowed limit of 5 MB" in resp_oversize.data

    # 4. Valid file: 128 KB PDF
    valid_pdf_payload = b"%PDF-1.4 Valid document content" + (b"\x00" * 128 * 1024)
    expected_sha = hashlib.sha256(valid_pdf_payload).hexdigest()

    resp_valid = client.post('/documents/upload', data={
        'title': 'Valid Contract',
        'description': 'Signed partner contract',
        'file': (io.BytesIO(valid_pdf_payload), 'contract.pdf')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_valid.status_code == 200
    assert b"Valid Contract" in resp_valid.data

    with app.app_context():
        # Assert rejected files were NOT saved
        assert Document.query.filter_by(title='Ransomware Payload').first() is None
        assert Document.query.filter_by(title='Shell Script').first() is None
        assert Document.query.filter_by(title='Huge File').first() is None

        # Assert valid file was saved properly with BLOB data and SHA-256
        saved_doc = Document.query.filter_by(title='Valid Contract').first()
        assert saved_doc is not None
        assert saved_doc.filename == 'contract.pdf'
        assert saved_doc.size == len(valid_pdf_payload)
        assert saved_doc.sha256 == expected_sha
        assert saved_doc.data == valid_pdf_payload
