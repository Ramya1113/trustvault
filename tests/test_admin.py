"""
Comprehensive tests for Admin Blueprint (app/blueprints/admin.py):
1. User management for own org:
   - List users
   - Create user with role
   - Deactivate / reactivate user
   - Change user role
   - Safety rule: Cannot demote or deactivate the last active admin
   - Cross-tenant user access rejected
2. Audit trail page:
   - Strictly scoped to own org
   - Search and filtering (by action, actor, target_type, outcome)
   - 'Verify chain' functionality: OK when intact, detects broken entry when tampered
3. Org-wide document list:
   - Shows all active docs in org
   - Tenant isolation
   - Search filter and deleted docs toggle
4. Non-admin roles (owner, viewer) hitting admin URLs:
   - Aborts with 403 Forbidden
   - Denied attempts logged in tamper-evident audit log
"""

import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AuditLog
from app.audit import log_event
from config import Config


class AdminTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create test application and in-memory database."""
    app = create_app(AdminTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def setup_admin_data(app):
    """
    Set up organizations, users, and documents for admin testing.
    """
    with app.app_context():
        # Organization 1: Acme
        org1 = Organization(name="Acme Corp")
        # Organization 2: Beta
        org2 = Organization(name="Beta Industries")
        db.session.add_all([org1, org2])
        db.session.flush()

        # Acme Users
        admin1 = User(org_id=org1.id, username="acme_admin1", email="admin1@acme.com", role="admin")
        admin1.set_password("AdminPass1234!")

        admin2 = User(org_id=org1.id, username="acme_admin2", email="admin2@acme.com", role="admin")
        admin2.set_password("AdminPass1234!")

        owner1 = User(org_id=org1.id, username="acme_owner", email="owner@acme.com", role="owner")
        owner1.set_password("OwnerPass1234!")

        viewer1 = User(org_id=org1.id, username="acme_viewer", email="viewer@acme.com", role="viewer")
        viewer1.set_password("ViewerPass1234!")

        # Beta Users (Cross-tenant)
        beta_admin = User(org_id=org2.id, username="beta_admin", email="admin@beta.com", role="admin")
        beta_admin.set_password("BetaAdminPass1234!")

        beta_viewer = User(org_id=org2.id, username="beta_viewer", email="viewer@beta.com", role="viewer")
        beta_viewer.set_password("BetaViewerPass1234!")

        db.session.add_all([admin1, admin2, owner1, viewer1, beta_admin, beta_viewer])
        db.session.flush()

        # Acme Documents
        doc1 = Document(
            org_id=org1.id,
            owner_id=owner1.id,
            title="Q3 Financials",
            description="Quarterly financial statements",
            filename="q3.pdf",
            mime_type="application/pdf",
            size=1024,
            sha256="a" * 64,
            data=b"financial report data"
        )
        doc2 = Document(
            org_id=org1.id,
            owner_id=admin1.id,
            title="HR Guidelines",
            description="Company handbook",
            filename="handbook.docx",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            size=2048,
            sha256="b" * 64,
            data=b"hr guidelines data"
        )
        # Soft-deleted doc
        doc3_deleted = Document(
            org_id=org1.id,
            owner_id=owner1.id,
            title="Draft Strategy",
            description="Old strategy document",
            filename="strategy.txt",
            mime_type="text/plain",
            size=512,
            sha256="c" * 64,
            data=b"deleted strategy",
            deleted_at=db.func.current_timestamp()
        )

        # Beta Document
        beta_doc = Document(
            org_id=org2.id,
            owner_id=beta_admin.id,
            title="Beta Secret Roadmap",
            description="Beta confidential",
            filename="roadmap.pdf",
            mime_type="application/pdf",
            size=4096,
            sha256="d" * 64,
            data=b"beta confidential data"
        )

        db.session.add_all([doc1, doc2, doc3_deleted, beta_doc])
        db.session.commit()

        return {
            'org1_id': org1.id,
            'org2_id': org2.id,
            'admin1_id': admin1.id,
            'admin2_id': admin2.id,
            'owner1_id': owner1.id,
            'viewer1_id': viewer1.id,
            'beta_admin_id': beta_admin.id,
            'beta_viewer_id': beta_viewer.id,
            'doc1_id': doc1.id,
            'doc2_id': doc2.id,
            'doc3_id': doc3_deleted.id,
            'beta_doc_id': beta_doc.id,
        }


def login_as(client, username, password):
    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


# =============================================================================
# 1. User Management Tests
# =============================================================================

def test_admin_can_view_users_list(client, setup_admin_data, app):
    """Admin can view the user roster for their own organization."""
    login_as(client, "acme_admin1", "AdminPass1234!")

    resp = client.get('/admin/users')
    assert resp.status_code == 200
    assert b"acme_admin1" in resp.data
    assert b"acme_owner" in resp.data
    assert b"acme_viewer" in resp.data
    # Zero cross-tenant leakage
    assert b"beta_admin" not in resp.data
    assert b"beta_viewer" not in resp.data

    with app.app_context():
        log = AuditLog.query.filter_by(action="user.list", org_id=setup_admin_data['org1_id']).first()
        assert log is not None
        assert log.outcome == "allowed"


def test_admin_can_create_user(client, setup_admin_data, app):
    """Admin can register a new user with role in their own organization."""
    ctx = setup_admin_data
    login_as(client, "acme_admin1", "AdminPass1234!")

    resp = client.post('/admin/users/create', data={
        'username': 'new_acme_user',
        'email': 'new_user@acme.com',
        'password': 'SecurePassword123!',
        'role': 'owner'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"User &#39;new_acme_user&#39; created successfully" in resp.data or b"created successfully" in resp.data

    with app.app_context():
        new_u = User.query.filter_by(username='new_acme_user').first()
        assert new_u is not None
        assert new_u.org_id == ctx['org1_id']
        assert new_u.role == 'owner'
        assert new_u.is_active is True
        assert new_u.check_password('SecurePassword123!')

        log = AuditLog.query.filter_by(action="user.create", target_id=new_u.id).first()
        assert log is not None
        assert log.outcome == "allowed"
        assert "new_acme_user" in log.detail


def test_admin_can_deactivate_and_reactivate_user(client, setup_admin_data, app):
    """Admin can deactivate a colleague, and then reactivate them."""
    ctx = setup_admin_data
    viewer1_id = ctx['viewer1_id']
    login_as(client, "acme_admin1", "AdminPass1234!")

    # Deactivate
    resp = client.post(f'/admin/users/{viewer1_id}/toggle-status', follow_redirects=True)
    assert resp.status_code == 200
    assert b"has been deactivated" in resp.data

    with app.app_context():
        u = db.session.get(User, viewer1_id)
        assert u.is_active is False

        log = AuditLog.query.filter_by(action="user.deactivate", target_id=viewer1_id).first()
        assert log is not None
        assert log.outcome == "allowed"

    # Reactivate
    resp2 = client.post(f'/admin/users/{viewer1_id}/toggle-status', follow_redirects=True)
    assert resp2.status_code == 200
    assert b"has been reactivated" in resp2.data

    with app.app_context():
        u = db.session.get(User, viewer1_id)
        assert u.is_active is True

        log2 = AuditLog.query.filter_by(action="user.reactivate", target_id=viewer1_id).first()
        assert log2 is not None
        assert log2.outcome == "allowed"


def test_admin_cannot_deactivate_last_active_admin(client, setup_admin_data, app):
    """
    Safety Rule: Admin cannot deactivate the last active admin.
    When two admins exist, deactivating one leaves one. Deactivating the last must be rejected.
    """
    ctx = setup_admin_data
    admin1_id = ctx['admin1_id']
    admin2_id = ctx['admin2_id']
    login_as(client, "acme_admin1", "AdminPass1234!")

    # Deactivate admin2 (leaves 1 active admin: admin1)
    resp = client.post(f'/admin/users/{admin2_id}/toggle-status', follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        a2 = db.session.get(User, admin2_id)
        assert a2.is_active is False

    # Now attempt to deactivate admin1 (the last active admin)
    resp_last = client.post(f'/admin/users/{admin1_id}/toggle-status', follow_redirects=True)
    assert resp_last.status_code == 200
    assert b"Cannot deactivate the only active administrator" in resp_last.data

    with app.app_context():
        a1 = db.session.get(User, admin1_id)
        assert a1.is_active is True  # Must remain active!

        # Check denied audit log
        log = AuditLog.query.filter_by(action="user.deactivate", target_id=admin1_id, outcome="denied").first()
        assert log is not None
        assert "Blocked attempt" in log.detail or "denied" in log.detail.lower()


def test_admin_cannot_demote_last_active_admin(client, setup_admin_data, app):
    """
    Safety Rule: Admin cannot demote the last active admin.
    """
    ctx = setup_admin_data
    admin1_id = ctx['admin1_id']
    admin2_id = ctx['admin2_id']
    login_as(client, "acme_admin1", "AdminPass1234!")

    # Deactivate admin2 so admin1 is the sole active admin
    client.post(f'/admin/users/{admin2_id}/toggle-status')

    # Try to demote admin1 to viewer
    resp = client.post(f'/admin/users/{admin1_id}/change-role', data={
        'role': 'viewer'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Cannot demote the only active administrator" in resp.data

    with app.app_context():
        a1 = db.session.get(User, admin1_id)
        assert a1.role == 'admin'  # Must NOT be demoted!

        log = AuditLog.query.filter_by(action="user.change_role", target_id=admin1_id, outcome="denied").first()
        assert log is not None


def test_admin_can_change_role_of_other_user(client, setup_admin_data, app):
    """Admin can change a user's role (e.g. viewer -> owner)."""
    ctx = setup_admin_data
    viewer1_id = ctx['viewer1_id']
    login_as(client, "acme_admin1", "AdminPass1234!")

    resp = client.post(f'/admin/users/{viewer1_id}/change-role', data={
        'role': 'owner'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Updated role" in resp.data

    with app.app_context():
        u = db.session.get(User, viewer1_id)
        assert u.role == 'owner'

        log = AuditLog.query.filter_by(action="user.change_role", target_id=viewer1_id, outcome="allowed").first()
        assert log is not None
        assert "from 'viewer' to 'owner'" in log.detail


def test_admin_cannot_manage_cross_tenant_users(client, setup_admin_data, app):
    """Admin of Acme cannot toggle status or change role of a Beta user (404 and logged)."""
    ctx = setup_admin_data
    beta_viewer_id = ctx['beta_viewer_id']
    login_as(client, "acme_admin1", "AdminPass1234!")

    # Attempt status toggle
    resp1 = client.post(f'/admin/users/{beta_viewer_id}/toggle-status')
    assert resp1.status_code == 404

    # Attempt role change
    resp2 = client.post(f'/admin/users/{beta_viewer_id}/change-role', data={'role': 'admin'})
    assert resp2.status_code == 404

    with app.app_context():
        denied_logs = AuditLog.query.filter_by(target_id=beta_viewer_id, outcome="denied").all()
        assert len(denied_logs) >= 2


# =============================================================================
# 2. Audit Trail & Hash Chain Verification Tests
# =============================================================================

def test_admin_audit_trail_view_and_filtering(client, setup_admin_data, app):
    """Admin can view the audit trail and apply filters."""
    ctx = setup_admin_data
    org1_id = ctx['org1_id']
    org2_id = ctx['org2_id']

    # Generate custom audit events
    with app.app_context():
        log_event(ctx['admin1_id'], "custom.action_one", target_type="document", target_id=ctx['doc1_id'], outcome="allowed", detail="Acme event 1", org_id=org1_id)
        log_event(ctx['owner1_id'], "custom.action_two", target_type="document", target_id=ctx['doc1_id'], outcome="denied", detail="Acme event 2", org_id=org1_id)
        log_event(ctx['beta_admin_id'], "beta.exclusive_action", target_type="document", target_id=ctx['beta_doc_id'], outcome="allowed", detail="Beta secret event", org_id=org2_id)

    login_as(client, "acme_admin1", "AdminPass1234!")

    # View full audit trail
    resp = client.get('/admin/audit')
    assert resp.status_code == 200
    assert b"custom.action_one" in resp.data
    assert b"custom.action_two" in resp.data
    # Cross-tenant data isolation: Beta secret event MUST NOT appear
    assert b"beta.exclusive_action" not in resp.data

    # Filter by outcome=denied
    resp_denied = client.get('/admin/audit?outcome=denied')
    assert resp_denied.status_code == 200
    assert b"Acme event 2" in resp_denied.data
    assert b"Acme event 1" not in resp_denied.data

    # Filter by action=custom.action_one
    resp_action = client.get('/admin/audit?action=custom.action_one')
    assert resp_action.status_code == 200
    assert b"Acme event 1" in resp_action.data
    assert b"Acme event 2" not in resp_action.data


def test_audit_chain_verification_intact_and_tampered(client, setup_admin_data, app):
    """
    Test 'Verify chain' button:
    1. Initially intact -> passes and displays OK
    2. Tampered directly in database -> fails and identifies broken entry
    """
    ctx = setup_admin_data
    org1_id = ctx['org1_id']

    # Log events
    with app.app_context():
        for i in range(5):
            log_event(
                actor=ctx['admin1_id'],
                action=f"audit.test.event_{i}",
                target_type="system",
                target_id=i,
                outcome="allowed",
                detail=f"Log item {i}",
                org_id=org1_id
            )

    login_as(client, "acme_admin1", "AdminPass1234!")

    # 1. Verify intact chain
    resp = client.post('/admin/audit/verify', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Chain Verification Passed: OK" in resp.data or b"verified: all records are intact" in resp.data

    # 2. Tamper with a record directly in DB (bypass application models to simulate SQL tamper)
    with app.app_context():
        # Fetch an entry in org1 to tamper with
        target_entry = AuditLog.query.filter_by(org_id=org1_id, action="audit.test.event_2").first()
        assert target_entry is not None
        tampered_id = target_entry.id

        # Tamper using raw connection to bypass any SQLAlchemy ORM listener
        with db.engine.connect() as conn:
            conn.execute(
                db.text("UPDATE audit_logs SET detail = :detail WHERE id = :id"),
                {"detail": "TAMPERED DATA IN DATABASE", "id": tampered_id}
            )
            conn.commit()

    # 3. Verify tampered chain
    resp_tampered = client.post('/admin/audit/verify', follow_redirects=True)
    assert resp_tampered.status_code == 200
    assert b"Chain Verification FAILED" in resp_tampered.data or b"integrity compromised" in resp_tampered.data
    assert str(tampered_id).encode() in resp_tampered.data


# =============================================================================
# 3. Org-Wide Document List Tests
# =============================================================================

def test_admin_org_documents_list(client, setup_admin_data, app):
    """Admin can view all documents across the organization."""
    ctx = setup_admin_data
    login_as(client, "acme_admin1", "AdminPass1234!")

    resp = client.get('/admin/documents')
    assert resp.status_code == 200
    # Shows both doc1 (owned by owner1) and doc2 (owned by admin1)
    assert b"Q3 Financials" in resp.data
    assert b"HR Guidelines" in resp.data
    # Excludes Beta's secret roadmap
    assert b"Beta Secret Roadmap" not in resp.data
    # Excludes soft-deleted document by default
    assert b"Draft Strategy" not in resp.data

    # Show deleted documents
    resp_deleted = client.get('/admin/documents?show_deleted=1')
    assert resp_deleted.status_code == 200
    assert b"Draft Strategy" in resp_deleted.data

    # Search filter
    resp_search = client.get('/admin/documents?q=Financials')
    assert resp_search.status_code == 200
    assert b"Q3 Financials" in resp_search.data
    assert b"HR Guidelines" not in resp_search.data


# =============================================================================
# 4. Access Control & Non-Admin Rejection Tests
# =============================================================================

@pytest.mark.parametrize("route,method,post_data", [
    ('/admin/users', 'GET', None),
    ('/admin/users/create', 'POST', {'username': 'hacker', 'email': 'hacker@hack.com', 'password': 'Password123!', 'role': 'admin'}),
    ('/admin/audit', 'GET', None),
    ('/admin/audit/verify', 'POST', {}),
    ('/admin/documents', 'GET', None),
])
def test_non_admin_roles_strictly_denied(client, setup_admin_data, app, route, method, post_data):
    """
    Non-admin roles (owner, viewer) attempting to access admin routes:
    - Receive HTTP 403 Forbidden
    - Have their denied attempt recorded in the audit log
    """
    ctx = setup_admin_data

    # Test as Owner
    login_as(client, "acme_owner", "OwnerPass1234!")
    if method == 'GET':
        resp = client.get(route)
    else:
        resp = client.post(route, data=post_data)
    assert resp.status_code == 403

    # Test as Viewer
    login_as(client, "acme_viewer", "ViewerPass1234!")
    if method == 'GET':
        resp2 = client.get(route)
    else:
        resp2 = client.post(route, data=post_data)
    assert resp2.status_code == 403

    # Verify denied audit entries
    with app.app_context():
        denied_logs = AuditLog.query.filter_by(org_id=ctx['org1_id'], outcome="denied").all()
        assert len(denied_logs) > 0


def test_unauthenticated_user_redirected_to_login(client):
    """Unauthenticated guests cannot access admin endpoints."""
    resp = client.get('/admin/users')
    assert resp.status_code == 302
    assert '/auth/login' in resp.headers.get('Location', '')
