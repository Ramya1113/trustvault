"""
Comprehensive tests for document access sharing in app/blueprints/sharing.py:
- Granting read or edit access within the same organization
- Changing permissions between read and edit
- Revoking access with immediate effect on subsequent requests
- Strict 403 Forbidden and audit logging for viewers and non-owners
- Rejection of cross-tenant sharing attempts
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant, AuditLog
from config import Config


class SharingTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create test application and in-memory database."""
    app = create_app(SharingTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def setup_sharing_data(app):
    """
    Set up two organizations with users and documents for sharing tests.
    """
    with app.app_context():
        # Organization 1: Acme
        org1 = Organization(name="Acme Corp")
        # Organization 2: Beta
        org2 = Organization(name="Beta Corp")
        db.session.add_all([org1, org2])
        db.session.flush()

        # Users in Acme
        admin1 = User(org_id=org1.id, username="acme_admin", email="admin@acme.com", role="admin")
        admin1.set_password("AdminPass1234!")

        doc_owner1 = User(org_id=org1.id, username="acme_owner", email="owner@acme.com", role="owner")
        doc_owner1.set_password("OwnerPass1234!")

        other_owner1 = User(org_id=org1.id, username="acme_other_owner", email="other_owner@acme.com", role="owner")
        other_owner1.set_password("OtherOwnerPass1234!")

        viewer1 = User(org_id=org1.id, username="acme_viewer1", email="viewer1@acme.com", role="viewer")
        viewer1.set_password("ViewerPass1234!")

        viewer2 = User(org_id=org1.id, username="acme_viewer2", email="viewer2@acme.com", role="viewer")
        viewer2.set_password("ViewerPass1234!")

        # User in Beta (Cross-tenant)
        beta_user = User(org_id=org2.id, username="beta_user", email="user@beta.com", role="viewer")
        beta_user.set_password("BetaPass1234!")

        db.session.add_all([admin1, doc_owner1, other_owner1, viewer1, viewer2, beta_user])
        db.session.flush()

        # Document in Acme owned by doc_owner1
        doc1 = Document(
            org_id=org1.id,
            owner_id=doc_owner1.id,
            title="Project Roadmap",
            filename="roadmap.pdf",
            size=100,
            sha256="roadmaphash",
            data=b"roadmap data"
        )
        db.session.add(doc1)
        db.session.commit()

        return {
            'org1_id': org1.id,
            'org2_id': org2.id,
            'admin1_id': admin1.id,
            'doc_owner1_id': doc_owner1.id,
            'other_owner1_id': other_owner1.id,
            'viewer1_id': viewer1.id,
            'viewer2_id': viewer2.id,
            'beta_user_id': beta_user.id,
            'doc1_id': doc1.id,
        }


def login_as(client, username, password):
    """Helper to authenticate a user."""
    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


# -----------------------------------------------------------------------------
# Grant Access Tests
# -----------------------------------------------------------------------------

def test_owner_can_grant_read_and_edit_access(client, setup_sharing_data, app):
    """
    Verify document owner can grant read or edit access to a user in the same org.
    Verify audit log records the grant with target user details.
    """
    ctx = setup_sharing_data
    doc_id = ctx['doc1_id']
    viewer1_id = ctx['viewer1_id']

    login_as(client, "acme_owner", "OwnerPass1234!")

    # 1. Grant read access to viewer1
    grant_resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': viewer1_id,
        'permission': 'read'
    }, follow_redirects=True)

    assert grant_resp.status_code == 200
    assert b"Granted Read access to &#39;acme_viewer1&#39;" in grant_resp.data or b"Granted Read access to 'acme_viewer1'" in grant_resp.data

    with app.app_context():
        grant = AccessGrant.query.filter_by(
            document_id=doc_id,
            user_id=viewer1_id,
            revoked_at=None
        ).first()
        assert grant is not None
        assert grant.permission == 'read'
        assert grant.granted_by == ctx['doc_owner1_id']

        # Verify audit log
        log = AuditLog.query.filter_by(action="access.grant", target_id=grant.id).first()
        assert log is not None
        assert log.outcome == "allowed"
        assert "acme_viewer1" in log.detail
        assert "read" in log.detail

    # 2. Verify viewer1 can now view and download the document
    client.get('/auth/logout')
    login_as(client, "acme_viewer1", "ViewerPass1234!")

    view_resp = client.get(f'/documents/{doc_id}')
    assert view_resp.status_code == 200
    assert b"Project Roadmap" in view_resp.data

    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200

    # But viewer1 cannot edit with read-only grant
    edit_resp = client.get(f'/documents/{doc_id}/edit')
    assert edit_resp.status_code == 403


def test_cannot_grant_access_to_cross_tenant_user(client, setup_sharing_data, app):
    """
    Verify user cannot grant access to a user in another organization.
    """
    ctx = setup_sharing_data
    doc_id = ctx['doc1_id']
    beta_user_id = ctx['beta_user_id']

    login_as(client, "acme_owner", "OwnerPass1234!")

    resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': beta_user_id,
        'permission': 'read'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Target user not found in your organization" in resp.data

    with app.app_context():
        # Verify no grant was created
        grant = AccessGrant.query.filter_by(document_id=doc_id, user_id=beta_user_id).first()
        assert grant is None


# -----------------------------------------------------------------------------
# Change Permission Tests
# -----------------------------------------------------------------------------

def test_change_permission_from_read_to_edit(client, setup_sharing_data, app):
    """
    Verify owner can change grant permission from 'read' to 'edit'.
    Target user immediately gains edit capability.
    """
    ctx = setup_sharing_data
    doc_id = ctx['doc1_id']
    viewer1_id = ctx['viewer1_id']

    with app.app_context():
        # Initial read grant
        grant = AccessGrant(
            document_id=doc_id,
            user_id=viewer1_id,
            permission='read',
            granted_by=ctx['doc_owner1_id']
        )
        db.session.add(grant)
        db.session.commit()
        grant_id = grant.id

    login_as(client, "acme_owner", "OwnerPass1234!")

    # Change permission to 'edit'
    resp = client.post(f'/documents/{doc_id}/sharing/{grant_id}/change', data={
        'permission': 'edit'
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        updated_grant = db.session.get(AccessGrant, grant_id)
        assert updated_grant.permission == 'edit'

        # Verify audit log
        log = AuditLog.query.filter_by(action="access.change", target_id=grant_id).first()
        assert log is not None
        assert "read" in log.detail
        assert "edit" in log.detail
        assert "acme_viewer1" in log.detail

    # Verify viewer1 can now edit the document
    client.get('/auth/logout')
    login_as(client, "acme_viewer1", "ViewerPass1234!")

    edit_resp = client.get(f'/documents/{doc_id}/edit')
    assert edit_resp.status_code == 200


# -----------------------------------------------------------------------------
# Revoke Access Tests
# -----------------------------------------------------------------------------

def test_revoke_access_takes_effect_immediately(client, setup_sharing_data, app):
    """
    Verify revoking access sets revoked_at and immediately denies access on the next request.
    """
    ctx = setup_sharing_data
    doc_id = ctx['doc1_id']
    viewer1_id = ctx['viewer1_id']

    with app.app_context():
        grant = AccessGrant(
            document_id=doc_id,
            user_id=viewer1_id,
            permission='read',
            granted_by=ctx['doc_owner1_id']
        )
        db.session.add(grant)
        db.session.commit()
        grant_id = grant.id

    # 1. Confirm viewer1 currently has view access
    login_as(client, "acme_viewer1", "ViewerPass1234!")
    assert client.get(f'/documents/{doc_id}').status_code == 200
    client.get('/auth/logout')

    # 2. Owner revokes access
    login_as(client, "acme_owner", "OwnerPass1234!")
    revoke_resp = client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke', follow_redirects=True)
    assert revoke_resp.status_code == 200

    with app.app_context():
        revoked_grant = db.session.get(AccessGrant, grant_id)
        assert revoked_grant.is_active is False
        assert revoked_grant.revoked_at is not None

        # Verify audit log
        log = AuditLog.query.filter_by(action="access.revoke", target_id=grant_id).first()
        assert log is not None
        assert "acme_viewer1" in log.detail

    # 3. Viewer1 makes request on the VERY NEXT request -> IMMEDIATELY DENIED (403)
    client.get('/auth/logout')
    login_as(client, "acme_viewer1", "ViewerPass1234!")

    # Attempt to view document
    next_req_resp = client.get(f'/documents/{doc_id}')
    assert next_req_resp.status_code == 403

    # Document also disappears from viewer1's document list
    list_resp = client.get('/documents/')
    assert b"Project Roadmap" not in list_resp.data


# -----------------------------------------------------------------------------
# Role Authorization Enforcement (Viewers & Non-owners Denied)
# -----------------------------------------------------------------------------

def test_viewer_and_non_owner_access_management_denied(client, setup_sharing_data, app):
    """
    Verify viewers and non-owners hitting sharing URLs directly receive 403 Forbidden,
    and denied attempts are recorded in the audit log.
    """
    ctx = setup_sharing_data
    doc_id = ctx['doc1_id']
    viewer1_id = ctx['viewer1_id']

    with app.app_context():
        # Give viewer1 edit grant on doc1 (still not owner, cannot manage_access)
        grant = AccessGrant(
            document_id=doc_id,
            user_id=viewer1_id,
            permission='edit',
            granted_by=ctx['doc_owner1_id']
        )
        db.session.add(grant)
        db.session.commit()
        grant_id = grant.id

    # 1. Viewer attempts GET /documents/<doc_id>/sharing/
    login_as(client, "acme_viewer1", "ViewerPass1234!")
    resp_get = client.get(f'/documents/{doc_id}/sharing/')
    assert resp_get.status_code == 403

    # Viewer attempts POST /documents/<doc_id>/sharing/grant
    resp_grant = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': ctx['viewer2_id'],
        'permission': 'read'
    })
    assert resp_grant.status_code == 403

    # Viewer attempts POST /documents/<doc_id>/sharing/<grant_id>/change
    resp_change = client.post(f'/documents/{doc_id}/sharing/{grant_id}/change', data={
        'permission': 'read'
    })
    assert resp_change.status_code == 403

    # Viewer attempts POST /documents/<doc_id>/sharing/<grant_id>/revoke
    resp_revoke = client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke')
    assert resp_revoke.status_code == 403

    # 2. Non-owner (other owner in same org) attempts access management -> 403
    client.get('/auth/logout')
    login_as(client, "acme_other_owner", "OtherOwnerPass1234!")

    resp_other_owner = client.get(f'/documents/{doc_id}/sharing/')
    assert resp_other_owner.status_code == 403

    # 3. Verify denied audit logs were recorded
    with app.app_context():
        denied_logs = AuditLog.query.filter_by(
            action="document.manage_access",
            target_id=doc_id,
            outcome="denied"
        ).all()
        assert len(denied_logs) >= 4
