"""
Comprehensive matrix table tests for the centralized authorization engine in app/permissions.py.

Tests every combination of:
- Role: admin, owner, viewer
- Action: view, download, edit, delete, manage_access, manage_users, view_audit
- Relation/Context: owner, granted_read, granted_edit, not_granted, other_tenant
Plus tests for soft-deleted documents, inactive users, and the require() helper/decorator.
"""

from datetime import datetime, timezone
import pytest
from werkzeug.exceptions import Forbidden
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant
from app.permissions import can, require
from config import Config


class PermTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture(scope='module')
def app():
    """Create test application and in-memory database once for this test module."""
    app = create_app(PermTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='module')
def setup_tenants(app):
    """
    Set up two isolated organizations with users and documents for permission testing.
    Returns IDs to avoid DetachedInstanceError across session boundaries.
    """
    with app.app_context():
        # Tenant 1: Acme
        org1 = Organization(name="Acme Corp")
        # Tenant 2: Beta (for cross-tenant tests)
        org2 = Organization(name="Beta Corp")
        db.session.add_all([org1, org2])
        db.session.flush()

        # Users in Tenant 1
        admin1 = User(org_id=org1.id, username="admin1", email="admin1@acme.com", role="admin")
        admin1.set_password("Pass12345678!")

        doc_owner1 = User(org_id=org1.id, username="owner1", email="owner1@acme.com", role="owner")
        doc_owner1.set_password("Pass12345678!")

        non_owner1 = User(org_id=org1.id, username="nonowner1", email="nonowner1@acme.com", role="owner")
        non_owner1.set_password("Pass12345678!")

        viewer1 = User(org_id=org1.id, username="viewer1", email="viewer1@acme.com", role="viewer")
        viewer1.set_password("Pass12345678!")

        # Viewer who somehow owns a document
        viewer_owner = User(org_id=org1.id, username="viewer_owner", email="vo@acme.com", role="viewer")
        viewer_owner.set_password("Pass12345678!")

        # Inactive user
        inactive1 = User(org_id=org1.id, username="inactive1", email="in@acme.com", role="admin", is_active=False)
        inactive1.set_password("Pass12345678!")

        # Users in Tenant 2 (Cross-tenant)
        admin2 = User(org_id=org2.id, username="admin2", email="admin2@beta.com", role="admin")
        admin2.set_password("Pass12345678!")

        db.session.add_all([admin1, doc_owner1, non_owner1, viewer1, viewer_owner, inactive1, admin2])
        db.session.flush()

        # Document in Tenant 1 owned by doc_owner1
        doc1 = Document(
            org_id=org1.id,
            owner_id=doc_owner1.id,
            title="Acme Specs",
            filename="specs.pdf",
            size=100,
            sha256="abc123hash",
            data=b"binarypayload"
        )
        # Document in Tenant 1 owned by viewer_owner
        doc_viewer_owned = Document(
            org_id=org1.id,
            owner_id=viewer_owner.id,
            title="Viewer Doc",
            filename="viewer.pdf",
            size=100,
            sha256="def456hash",
            data=b"binarypayload"
        )
        # Document in Tenant 1 that is soft-deleted
        doc_deleted = Document(
            org_id=org1.id,
            owner_id=doc_owner1.id,
            title="Deleted Doc",
            filename="del.pdf",
            size=100,
            sha256="del789hash",
            data=b"binarypayload",
            deleted_at=datetime.now(timezone.utc)
        )
        # Document in Tenant 2
        doc_tenant2 = Document(
            org_id=org2.id,
            owner_id=admin2.id,
            title="Beta Financials",
            filename="beta.pdf",
            size=100,
            sha256="beta999hash",
            data=b"binarypayload"
        )

        db.session.add_all([doc1, doc_viewer_owned, doc_deleted, doc_tenant2])
        db.session.commit()

        return {
            'org1_id': org1.id,
            'org2_id': org2.id,
            'admin1_id': admin1.id,
            'doc_owner1_id': doc_owner1.id,
            'non_owner1_id': non_owner1.id,
            'viewer1_id': viewer1.id,
            'viewer_owner_id': viewer_owner.id,
            'inactive1_id': inactive1.id,
            'admin2_id': admin2.id,
            'doc1_id': doc1.id,
            'doc_viewer_owned_id': doc_viewer_owned.id,
            'doc_deleted_id': doc_deleted.id,
            'doc_tenant2_id': doc_tenant2.id,
        }


# =============================================================================
# FULL PERMISSION MATRIX TEST TABLE
# =============================================================================
MATRIX_CASES = [
    # -------------------------------------------------------------------------
    # ADMIN ROLE
    # Admins have full access to everything in their own org, zero access to other orgs.
    # -------------------------------------------------------------------------
    # Admin on own doc
    ('admin', 'view', 'owner', True),
    ('admin', 'download', 'owner', True),
    ('admin', 'edit', 'owner', True),
    ('admin', 'delete', 'owner', True),
    ('admin', 'manage_access', 'owner', True),
    ('admin', 'manage_users', 'owner', True),
    ('admin', 'view_audit', 'owner', True),

    # Admin on another user's doc (granted_read or not_granted makes no difference for admin in same org)
    ('admin', 'view', 'granted_read', True),
    ('admin', 'download', 'granted_read', True),
    ('admin', 'edit', 'granted_read', True),
    ('admin', 'delete', 'granted_read', True),
    ('admin', 'manage_access', 'granted_read', True),
    ('admin', 'manage_users', 'granted_read', True),
    ('admin', 'view_audit', 'granted_read', True),

    ('admin', 'view', 'not_granted', True),
    ('admin', 'download', 'not_granted', True),
    ('admin', 'edit', 'not_granted', True),
    ('admin', 'delete', 'not_granted', True),
    ('admin', 'manage_access', 'not_granted', True),
    ('admin', 'manage_users', 'not_granted', True),
    ('admin', 'view_audit', 'not_granted', True),

    # Admin on other tenant document (TENANT ISOLATION MUST DENY ALL)
    ('admin', 'view', 'other_tenant', False),
    ('admin', 'download', 'other_tenant', False),
    ('admin', 'edit', 'other_tenant', False),
    ('admin', 'delete', 'other_tenant', False),
    ('admin', 'manage_access', 'other_tenant', False),
    ('admin', 'manage_users', 'other_tenant', False),
    ('admin', 'view_audit', 'other_tenant', False),

    # -------------------------------------------------------------------------
    # OWNER ROLE
    # Owners can fully manage their own documents; need grants for other docs; never manage org users or audit.
    # -------------------------------------------------------------------------
    # Owner on document they own
    ('owner', 'view', 'owner', True),
    ('owner', 'download', 'owner', True),
    ('owner', 'edit', 'owner', True),
    ('owner', 'delete', 'owner', True),
    ('owner', 'manage_access', 'owner', True),
    ('owner', 'manage_users', 'owner', False),
    ('owner', 'view_audit', 'owner', False),

    # Owner on document owned by someone else with active 'read' grant
    ('owner', 'view', 'granted_read', True),
    ('owner', 'download', 'granted_read', True),
    ('owner', 'edit', 'granted_read', False),
    ('owner', 'delete', 'granted_read', False),
    ('owner', 'manage_access', 'granted_read', False),
    ('owner', 'manage_users', 'granted_read', False),
    ('owner', 'view_audit', 'granted_read', False),

    # Owner on document owned by someone else with active 'edit' grant
    ('owner', 'view', 'granted_edit', True),
    ('owner', 'download', 'granted_edit', True),
    ('owner', 'edit', 'granted_edit', True),
    ('owner', 'delete', 'granted_edit', False),
    ('owner', 'manage_access', 'granted_edit', False),
    ('owner', 'manage_users', 'granted_edit', False),
    ('owner', 'view_audit', 'granted_edit', False),

    # Owner on document with no grant
    ('owner', 'view', 'not_granted', False),
    ('owner', 'download', 'not_granted', False),
    ('owner', 'edit', 'not_granted', False),
    ('owner', 'delete', 'not_granted', False),
    ('owner', 'manage_access', 'not_granted', False),
    ('owner', 'manage_users', 'not_granted', False),
    ('owner', 'view_audit', 'not_granted', False),

    # Owner on other tenant document (TENANT ISOLATION)
    ('owner', 'view', 'other_tenant', False),
    ('owner', 'download', 'other_tenant', False),
    ('owner', 'edit', 'other_tenant', False),
    ('owner', 'delete', 'other_tenant', False),
    ('owner', 'manage_access', 'other_tenant', False),
    ('owner', 'manage_users', 'other_tenant', False),
    ('owner', 'view_audit', 'other_tenant', False),

    # -------------------------------------------------------------------------
    # VIEWER ROLE
    # Viewers can only view/download (or edit if given edit grant); NEVER manage_access or delete or manage users/audit.
    # -------------------------------------------------------------------------
    # Viewer on document they somehow own (viewers can NEVER manage_access!)
    ('viewer', 'view', 'owner', True),
    ('viewer', 'download', 'owner', True),
    ('viewer', 'edit', 'owner', True),
    ('viewer', 'delete', 'owner', True),
    ('viewer', 'manage_access', 'owner', False),  # Explicit rule: viewers can never manage_access
    ('viewer', 'manage_users', 'owner', False),
    ('viewer', 'view_audit', 'owner', False),

    # Viewer with active 'read' grant
    ('viewer', 'view', 'granted_read', True),
    ('viewer', 'download', 'granted_read', True),
    ('viewer', 'edit', 'granted_read', False),
    ('viewer', 'delete', 'granted_read', False),
    ('viewer', 'manage_access', 'granted_read', False),
    ('viewer', 'manage_users', 'granted_read', False),
    ('viewer', 'view_audit', 'granted_read', False),

    # Viewer with active 'edit' grant
    ('viewer', 'view', 'granted_edit', True),
    ('viewer', 'download', 'granted_edit', True),
    ('viewer', 'edit', 'granted_edit', True),
    ('viewer', 'delete', 'granted_edit', False),
    ('viewer', 'manage_access', 'granted_edit', False),
    ('viewer', 'manage_users', 'granted_edit', False),
    ('viewer', 'view_audit', 'granted_edit', False),

    # Viewer with no grant
    ('viewer', 'view', 'not_granted', False),
    ('viewer', 'download', 'not_granted', False),
    ('viewer', 'edit', 'not_granted', False),
    ('viewer', 'delete', 'not_granted', False),
    ('viewer', 'manage_access', 'not_granted', False),
    ('viewer', 'manage_users', 'not_granted', False),
    ('viewer', 'view_audit', 'not_granted', False),

    # Viewer on other tenant document (TENANT ISOLATION)
    ('viewer', 'view', 'other_tenant', False),
    ('viewer', 'download', 'other_tenant', False),
    ('viewer', 'edit', 'other_tenant', False),
    ('viewer', 'delete', 'other_tenant', False),
    ('viewer', 'manage_access', 'other_tenant', False),
    ('viewer', 'manage_users', 'other_tenant', False),
    ('viewer', 'view_audit', 'other_tenant', False),
]


@pytest.mark.parametrize("role,action,relationship,expected", MATRIX_CASES)
def test_full_permission_matrix(app, setup_tenants, role, action, relationship, expected):
    """
    Parametrized full matrix test verifying can(user, action, document).
    """
    with app.app_context():
        ctx = setup_tenants

        # 1. Fetch attached User instance
        if role == 'admin':
            user = db.session.get(User, ctx['admin1_id'])
        elif role == 'owner':
            user_id = ctx['doc_owner1_id'] if relationship == 'owner' else ctx['non_owner1_id']
            user = db.session.get(User, user_id)
        elif role == 'viewer':
            user_id = ctx['viewer_owner_id'] if relationship == 'owner' else ctx['viewer1_id']
            user = db.session.get(User, user_id)
        else:
            pytest.fail(f"Unknown role: {role}")

        # 2. Fetch attached Document instance
        if relationship == 'owner':
            doc_id = ctx['doc_viewer_owned_id'] if role == 'viewer' else ctx['doc1_id']
            doc = db.session.get(Document, doc_id)
        elif relationship == 'other_tenant':
            doc = db.session.get(Document, ctx['doc_tenant2_id'])
        else:
            doc = db.session.get(Document, ctx['doc1_id'])

        # 3. Handle access grant setup for non-owner tests
        created_grant = None
        if relationship in {'granted_read', 'granted_edit'}:
            perm = 'read' if relationship == 'granted_read' else 'edit'
            created_grant = AccessGrant(
                document_id=doc.id,
                user_id=user.id,
                permission=perm,
                granted_by=ctx['doc_owner1_id']
            )
            db.session.add(created_grant)
            db.session.commit()

        try:
            # 4. Target document: None for org actions unless testing other_tenant
            target_doc = doc if action in {'view', 'download', 'edit', 'delete', 'manage_access'} else None
            if relationship == 'other_tenant' and action in {'manage_users', 'view_audit'}:
                target_doc = doc

            # 5. Evaluate permission
            result = can(user, action, target_doc)
            assert result == expected, (
                f"Failed check: role={role}, action={action}, "
                f"relationship={relationship}. Expected {expected}, got {result}."
            )
        finally:
            # Clean up any grant added for this test case
            if created_grant is not None:
                db.session.delete(created_grant)
                db.session.commit()


def test_soft_deleted_document_denies_all_roles(app, setup_tenants):
    """
    Verify that soft-deleted documents deny all document actions, even for admin and owner.
    """
    with app.app_context():
        ctx = setup_tenants
        doc_del = db.session.get(Document, ctx['doc_deleted_id'])
        admin = db.session.get(User, ctx['admin1_id'])
        owner = db.session.get(User, ctx['doc_owner1_id'])
        viewer = db.session.get(User, ctx['viewer1_id'])
        actions = ['view', 'download', 'edit', 'delete', 'manage_access']

        for user in [admin, owner, viewer]:
            for action in actions:
                assert can(user, action, doc_del) is False


def test_inactive_user_denies_all_actions(app, setup_tenants):
    """
    Verify that inactive users are strictly denied all actions.
    """
    with app.app_context():
        ctx = setup_tenants
        inactive = db.session.get(User, ctx['inactive1_id'])
        doc = db.session.get(Document, ctx['doc1_id'])
        actions = ['view', 'download', 'edit', 'delete', 'manage_access', 'manage_users', 'view_audit']

        for action in actions:
            target_doc = doc if action not in {'manage_users', 'view_audit'} else None
            assert can(inactive, action, target_doc) is False


def test_revoked_grant_denies_access(app, setup_tenants):
    """
    Verify that revoking an access grant immediately denies view and edit permissions.
    """
    with app.app_context():
        ctx = setup_tenants
        doc = db.session.get(Document, ctx['doc1_id'])
        viewer = db.session.get(User, ctx['viewer1_id'])

        # Create active grant
        grant = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission='edit',
            granted_by=ctx['doc_owner1_id']
        )
        db.session.add(grant)
        db.session.commit()

        assert can(viewer, 'view', doc) is True
        assert can(viewer, 'edit', doc) is True

        # Revoke grant
        grant.revoke()
        db.session.commit()

        assert can(viewer, 'view', doc) is False
        assert can(viewer, 'edit', doc) is False

        # Cleanup
        db.session.delete(grant)
        db.session.commit()


def test_require_helper_and_decorator(app, setup_tenants):
    """
    Verify that require() aborts with HTTP 403 Forbidden when denied, and allows when permitted.
    """
    ctx = setup_tenants

    with app.app_context():
        doc = db.session.get(Document, ctx['doc1_id'])
        admin = db.session.get(User, ctx['admin1_id'])
        viewer = db.session.get(User, ctx['viewer1_id'])

    # 1. Inside a request context with an authenticated admin
    with app.test_request_context():
        from flask_login import login_user
        login_user(admin)

        # Admin is permitted -> require should succeed without raising
        require('view', doc)
        require('manage_users')

    # 2. Inside a request context with an ungranted viewer
    with app.test_request_context():
        from flask_login import login_user
        login_user(viewer)

        # Viewer has no grant -> require('view', doc) MUST abort with 403 Forbidden
        with pytest.raises(Forbidden):
            require('view', doc)

        # Viewer cannot manage users -> require('manage_users') MUST abort with 403 Forbidden
        with pytest.raises(Forbidden):
            require('manage_users')

    # 3. As a route decorator
    @require('view', doc)
    def view_handler():
        return "allowed"

    with app.test_request_context():
        from flask_login import login_user
        login_user(admin)
        assert view_handler() == "allowed"

    with app.test_request_context():
        from flask_login import login_user
        login_user(viewer)
        with pytest.raises(Forbidden):
            view_handler()
