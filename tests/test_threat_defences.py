"""
Threat Defense Tests:
Rigorous verification tests proving each defense against specific attack vectors.
"""
from datetime import datetime, timezone
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document, AccessGrant, AuditLog
from config import Config


class DefenseTestConfig(Config):
    """Configuration for threat defense verification."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Setup testing app and in-memory database."""
    app = create_app(DefenseTestConfig)
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


# -----------------------------------------------------------------------------
# 1. Deactivated user's existing logged-in session stops working on next request
# -----------------------------------------------------------------------------

def test_deactivated_user_session_stops_on_next_request(client, app):
    """
    Threat: Session hijacking / persistent access by rogue or terminated employees.
    Defense: load_user immediately returns None if user.is_active is False, and
    before_request invalidates and redirects existing session cookies.
    """
    with app.app_context():
        org = Organization(name="Defense Org 1")
        db.session.add(org)
        db.session.flush()

        user = User(org_id=org.id, username="active_employee", email="emp@def1.org", role="viewer")
        user.set_password("EmployeePassword123!")
        db.session.add(user)
        db.session.commit()

    # 1. Employee signs in
    login_resp = client.post('/auth/login', data={
        'username': 'active_employee',
        'password': 'EmployeePassword123!'
    }, follow_redirects=False)
    assert login_resp.status_code == 302

    # 2. Accesses dashboard while active
    dash_resp = client.get('/auth/dashboard')
    assert dash_resp.status_code == 200

    # 3. Admin deactivates the user
    with app.app_context():
        emp = User.query.filter_by(username='active_employee').first()
        emp.is_active = False
        db.session.commit()

    # 4. On the very next request with the existing session cookie, access is denied
    next_resp = client.get('/auth/dashboard', follow_redirects=False)
    assert next_resp.status_code == 302
    assert '/auth/login' in next_resp.headers['Location']

    # Document index also redirects to login
    docs_resp = client.get('/documents/', follow_redirects=False)
    assert docs_resp.status_code == 302
    assert '/auth/login' in docs_resp.headers['Location']


# -----------------------------------------------------------------------------
# 2. Soft-deleted document returns 404 on view, download, edit, delete, sharing
# -----------------------------------------------------------------------------

def test_soft_deleted_document_returns_404_on_all_endpoints(client, app):
    """
    Threat: Accessing soft-deleted / decommissioned confidential files.
    Defense: _get_document_or_abort and _get_document_for_manage_access strictly filter
    deleted_at=None, returning 404 on view, download, edit, delete, and all sharing URLs.
    """
    with app.app_context():
        org = Organization(name="Defense Org 2")
        db.session.add(org)
        db.session.flush()

        owner = User(org_id=org.id, username="owner_del", email="owner@def2.org", role="owner")
        owner.set_password("OwnerPassword123!")

        colleague = User(org_id=org.id, username="colleague_del", email="col@def2.org", role="viewer")
        colleague.set_password("ColleaguePassword123!")

        db.session.add_all([owner, colleague])
        db.session.flush()

        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="To Be Deleted Doc",
            filename="delete_me.pdf",
            mime_type="application/pdf",
            size=20,
            sha256="dummyhash",
            data=b"%PDF-1.4\ncontent"
        )
        db.session.add(doc)
        db.session.flush()

        grant = AccessGrant(
            document_id=doc.id,
            user_id=colleague.id,
            permission='read',
            granted_by=owner.id
        )
        db.session.add(grant)
        db.session.commit()

        doc_id = doc.id
        grant_id = grant.id

    # 1. Sign in as owner
    client.post('/auth/login', data={'username': 'owner_del', 'password': 'OwnerPassword123!'})

    # 2. Confirm accessible while active
    assert client.get(f'/documents/{doc_id}').status_code == 200
    assert client.get(f'/documents/{doc_id}/download').status_code == 200
    assert client.get(f'/documents/{doc_id}/edit').status_code == 200
    assert client.get(f'/documents/{doc_id}/sharing/').status_code == 200

    # 3. Soft-delete the document
    del_resp = client.post(f'/documents/{doc_id}/delete', follow_redirects=True)
    assert del_resp.status_code == 200

    # 4. Verify 404 on all endpoints
    # - View details
    assert client.get(f'/documents/{doc_id}').status_code == 404
    # - Download binary
    assert client.get(f'/documents/{doc_id}/download').status_code == 404
    # - Edit GET and POST
    assert client.get(f'/documents/{doc_id}/edit').status_code == 404
    assert client.post(f'/documents/{doc_id}/edit', data={'title': 'Tamper Title'}).status_code == 404
    # - Re-delete POST
    assert client.post(f'/documents/{doc_id}/delete').status_code == 404
    # - All sharing URLs
    assert client.get(f'/documents/{doc_id}/sharing/').status_code == 404
    assert client.post(f'/documents/{doc_id}/sharing/grant', data={'user_id': 2, 'permission': 'read'}).status_code == 404
    assert client.post(f'/documents/{doc_id}/sharing/{grant_id}/change', data={'permission': 'edit'}).status_code == 404
    assert client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke').status_code == 404


# -----------------------------------------------------------------------------
# 3. User cannot set their own role or org_id via form tampering
# -----------------------------------------------------------------------------

def test_user_cannot_set_role_or_org_id_via_form_fields(client, app):
    """
    Threat: Privilege escalation & cross-tenant account injection via hidden POST parameters.
    Defense: RegisterForm and CreateUserForm ignore injected org_id/role parameters.
    User is strictly bound to newly generated org.id on register and current_user.org_id on create.
    """
    # 1. Registration tampering: inject role='superadmin' and org_id=999
    reg_resp = client.post('/auth/register', data={
        'organization_name': 'Tamper Proof Corp',
        'username': 'tamper_candidate',
        'email': 'candidate@tamper.org',
        'password': 'CandidatePassword123!',
        'password_confirm': 'CandidatePassword123!',
        'role': 'superadmin',
        'org_id': 999
    }, follow_redirects=True)
    assert reg_resp.status_code == 200

    with app.app_context():
        new_org = Organization.query.filter_by(name='Tamper Proof Corp').first()
        registered_user = User.query.filter_by(username='tamper_candidate').first()
        assert registered_user is not None
        assert registered_user.org_id == new_org.id
        assert registered_user.org_id != 999
        assert registered_user.role == 'admin'  # Standard admin of own new org only
        admin_id = registered_user.id
        org_id = new_org.id

    # 2. User creation tampering: admin attempts to create colleague in another org
    with app.app_context():
        victim_org = Organization(name="Victim Org")
        db.session.add(victim_org)
        db.session.commit()
        victim_org_id = victim_org.id

    create_resp = client.post('/admin/users/create', data={
        'username': 'injected_colleague',
        'email': 'injected@tamper.org',
        'password': 'ColleaguePassword123!',
        'role': 'viewer',
        'org_id': victim_org_id  # Injected foreign org_id
    }, follow_redirects=True)
    assert create_resp.status_code == 200

    with app.app_context():
        created_user = User.query.filter_by(username='injected_colleague').first()
        assert created_user is not None
        # Must be bound to creator's org, NEVER victim org
        assert created_user.org_id == org_id
        assert created_user.org_id != victim_org_id

    # 3. Invalid role injection: role='superadmin' rejected
    bad_role_resp = client.post('/admin/users/create', data={
        'username': 'super_colleague',
        'email': 'super@tamper.org',
        'password': 'ColleaguePassword123!',
        'role': 'superadmin'
    }, follow_redirects=True)
    assert bad_role_resp.status_code == 200

    with app.app_context():
        assert User.query.filter_by(username='super_colleague').first() is None


# -----------------------------------------------------------------------------
# 4. Login ?next= parameter cannot redirect to an external site
# -----------------------------------------------------------------------------

def test_login_next_parameter_cannot_redirect_externally(client, app):
    """
    Threat: Open redirect phishing attacks chaining login authentication to external malware domains.
    Defense: is_safe_redirect_url validates that ?next= contains no scheme, no netloc,
    rejects protocol-relative prefixes (//, /\\, \\), defaulting safely to /auth/dashboard.
    """
    with app.app_context():
        org = Organization(name="Defense Org 4")
        db.session.add(org)
        db.session.flush()

        user = User(org_id=org.id, username="login_user", email="login@def4.org", role="owner")
        user.set_password("LoginPassword123!")
        db.session.add(user)
        db.session.commit()

    # 1. Legitimate relative same-site path is permitted
    legit_resp = client.post('/auth/login?next=/documents', data={
        'username': 'login_user',
        'password': 'LoginPassword123!'
    }, follow_redirects=False)
    assert legit_resp.status_code == 302
    assert legit_resp.headers['Location'] == '/documents'

    # 2. Hostile external targets are blocked and fallback to /auth/dashboard
    malicious_targets = [
        "http://attacker.com",
        "https://phishing.site/fake-login",
        "//attacker.com",
        "//attacker.com/documents",
        "/\\attacker.com",
        "\\attacker.com",
        "javascript:alert(document.cookie)"
    ]

    for target in malicious_targets:
        attack_resp = client.post(f'/auth/login?next={target}', data={
            'username': 'login_user',
            'password': 'LoginPassword123!'
        }, follow_redirects=False)
        assert attack_resp.status_code == 302
        assert attack_resp.headers['Location'] == '/auth/dashboard'


# -----------------------------------------------------------------------------
# 5. Document title or filename containing <script> is escaped (no XSS)
# -----------------------------------------------------------------------------

def test_xss_escaping_on_list_detail_and_audit_pages(client, app):
    """
    Threat: Stored Cross-Site Scripting (XSS) via document title, description, or filename.
    Defense: Jinja2 automatic HTML context escaping on all .html templates ensures
    HTML tags are converted to entities (&lt;script&gt;) and never executed as raw scripts.
    """
    xss_payload = '<script>alert("xss-vulnerability")</script>'

    with app.app_context():
        org = Organization(name="Defense Org 5")
        db.session.add(org)
        db.session.flush()

        admin = User(org_id=org.id, username="admin_xss", email="admin@def5.org", role="admin")
        admin.set_password("AdminPassword123!")
        db.session.add(admin)
        db.session.flush()

        doc_bytes = b"%PDF-1.4\nclean content"
        doc = Document(
            org_id=org.id,
            owner_id=admin.id,
            title=f"Quarterly Report {xss_payload}",
            description=f"Confidential notes {xss_payload}",
            filename=f"report_{xss_payload}.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="dummyhash",
            data=doc_bytes
        )
        db.session.add(doc)
        db.session.flush()

        # Audit log containing the payload
        from app.audit import log_event
        log_event(
            actor=admin,
            action="document.upload",
            target_type="document",
            target_id=doc.id,
            outcome="allowed",
            detail=f"Uploaded '{doc.title}' with filename '{doc.filename}'",
            org_id=org.id
        )
        db.session.commit()
        doc_id = doc.id

    client.post('/auth/login', data={'username': 'admin_xss', 'password': 'AdminPassword123!'})

    # 1. Document list page (/documents/)
    list_resp = client.get('/documents/')
    assert list_resp.status_code == 200
    list_html = list_resp.get_data(as_text=True)
    assert '<script>alert("xss-vulnerability")</script>' not in list_html
    assert '&lt;script&gt;alert(' in list_html

    # 2. Document detail page (/documents/<id>)
    detail_resp = client.get(f'/documents/{doc_id}')
    assert detail_resp.status_code == 200
    detail_html = detail_resp.get_data(as_text=True)
    assert '<script>alert("xss-vulnerability")</script>' not in detail_html
    assert '&lt;script&gt;alert(' in detail_html

    # 3. Admin documents list page (/admin/documents)
    admin_docs_resp = client.get('/admin/documents')
    assert admin_docs_resp.status_code == 200
    admin_docs_html = admin_docs_resp.get_data(as_text=True)
    assert '<script>alert("xss-vulnerability")</script>' not in admin_docs_html
    assert '&lt;script&gt;alert(' in admin_docs_html

    # 4. Admin audit log page (/admin/audit)
    audit_resp = client.get('/admin/audit')
    assert audit_resp.status_code == 200
    audit_html = audit_resp.get_data(as_text=True)
    assert '<script>alert("xss-vulnerability")</script>' not in audit_html
    assert '&lt;script&gt;alert(' in audit_html


# -----------------------------------------------------------------------------
# 6. Filename with quotes or newlines cannot inject headers in Content-Disposition
# -----------------------------------------------------------------------------

def test_filename_quotes_and_newlines_cannot_inject_headers(client, app):
    """
    Threat: HTTP response header splitting (CRLF injection) and parameter breaking via quotes in filenames.
    Defense: clean_filename sanitizes filenames with secure_filename() and strips \r, \n, and \",
    preventing any header injection or premature quotation parameter escapes.
    """
    with app.app_context():
        org = Organization(name="Defense Org 6")
        db.session.add(org)
        db.session.flush()

        owner = User(org_id=org.id, username="owner_crlf", email="owner@def6.org", role="owner")
        owner.set_password("OwnerPassword123!")
        db.session.add(owner)
        db.session.flush()

        doc_bytes = b"%PDF-1.4\nclean content"
        malicious_doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="CRLF Injected Doc",
            filename='exploit";\r\nSet-Cookie: evil_tracker=pwned\r\nX-Injected: true\r\nDummy: "clean.pdf',
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="dummyhash",
            data=doc_bytes
        )
        db.session.add(malicious_doc)
        db.session.commit()
        doc_id = malicious_doc.id

    client.post('/auth/login', data={'username': 'owner_crlf', 'password': 'OwnerPassword123!'})

    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200

    # Ensure no CRLF-injected headers were parsed as HTTP headers
    assert 'X-Injected' not in dl_resp.headers
    assert 'Dummy' not in dl_resp.headers
    assert 'evil_tracker=pwned' not in dl_resp.headers.get('Set-Cookie', '')

    content_disp = dl_resp.headers.get('Content-Disposition')
    assert content_disp is not None
    # Must not contain raw carriage return or line breaks
    assert '\r' not in content_disp
    assert '\n' not in content_disp
    # Verified filename safely quoted without unescaped quote breaks
    assert 'clean.pdf' in content_disp


# -----------------------------------------------------------------------------
# 7. Owner cannot grant access to a cross-tenant user or to a deactivated user
# -----------------------------------------------------------------------------

def test_owner_cannot_grant_access_to_cross_org_or_deactivated_user(client, app):
    """
    Threat: Cross-tenant data leakage and access grants to rogue deactivated accounts.
    Defense: grant_access strictly verifies target_user.org_id == current_user.org_id
    AND target_user.is_active is True, blocking and logging denied attempts if either fails.
    """
    with app.app_context():
        # Tenant 1
        org1 = Organization(name="Defense Org 7A")
        db.session.add(org1)
        db.session.flush()

        owner = User(org_id=org1.id, username="owner_tenant1", email="owner@def7a.org", role="owner")
        owner.set_password("OwnerPassword123!")

        deactivated_user = User(org_id=org1.id, username="deactivated_tenant1", email="deact@def7a.org", role="viewer", is_active=False)
        deactivated_user.set_password("DeactPassword123!")

        # Tenant 2
        org2 = Organization(name="Defense Org 7B")
        db.session.add(org2)
        db.session.flush()

        cross_tenant_user = User(org_id=org2.id, username="user_tenant2", email="user@def7b.org", role="viewer", is_active=True)
        cross_tenant_user.set_password("Tenant2Password123!")

        db.session.add_all([owner, deactivated_user, cross_tenant_user])
        db.session.flush()

        doc_bytes = b"%PDF-1.4\nclean content"
        doc = Document(
            org_id=org1.id,
            owner_id=owner.id,
            title="Tenant 1 Private Secrets",
            filename="private.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="dummyhash",
            data=doc_bytes
        )
        db.session.add(doc)
        db.session.commit()

        doc_id = doc.id
        cross_user_id = cross_tenant_user.id
        deact_user_id = deactivated_user.id

    client.post('/auth/login', data={'username': 'owner_tenant1', 'password': 'OwnerPassword123!'})

    # 1. Attempt to grant access to a user in another organization
    cross_resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': cross_user_id,
        'permission': 'read'
    }, follow_redirects=True)
    assert cross_resp.status_code == 200
    assert b"Target user not found in your organization" in cross_resp.data

    with app.app_context():
        cross_grant = AccessGrant.query.filter_by(document_id=doc_id, user_id=cross_user_id).first()
        assert cross_grant is None

    # 2. Attempt to grant access to a deactivated user in the same organization
    deact_resp = client.post(f'/documents/{doc_id}/sharing/grant', data={
        'user_id': deact_user_id,
        'permission': 'read'
    }, follow_redirects=True)
    assert deact_resp.status_code == 200
    assert b"Target user not found in your organization" in deact_resp.data

    with app.app_context():
        deact_grant = AccessGrant.query.filter_by(document_id=doc_id, user_id=deact_user_id).first()
        assert deact_grant is None


# -----------------------------------------------------------------------------
# 8. Viewer granted 'edit' and later revoked cannot edit on the next request
# -----------------------------------------------------------------------------

def test_revoked_edit_grant_viewer_cannot_edit_on_next_request(client, app):
    """
    Threat: Persistent access after permission revocation.
    Defense: can() and require() check revoked_at is None on every single request.
    Revocation immediately revokes edit capabilities on the very next request, returning 403.
    """
    with app.app_context():
        org = Organization(name="Defense Org 8")
        db.session.add(org)
        db.session.flush()

        owner = User(org_id=org.id, username="owner_def8", email="owner@def8.org", role="owner")
        owner.set_password("OwnerPassword123!")

        viewer = User(org_id=org.id, username="viewer_def8", email="viewer@def8.org", role="viewer")
        viewer.set_password("ViewerPassword123!")

        db.session.add_all([owner, viewer])
        db.session.flush()

        doc_bytes = b"%PDF-1.4\nclean content"
        doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Design Specification",
            filename="design.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="dummyhash",
            data=doc_bytes
        )
        db.session.add(doc)
        db.session.flush()

        # Grant 'edit' to viewer
        grant = AccessGrant(
            document_id=doc.id,
            user_id=viewer.id,
            permission='edit',
            granted_by=owner.id
        )
        db.session.add(grant)
        db.session.commit()

        doc_id = doc.id
        grant_id = grant.id

    # 1. Viewer logs in and verifies edit access is initially active
    client.post('/auth/login', data={'username': 'viewer_def8', 'password': 'ViewerPassword123!'})
    edit_page_resp = client.get(f'/documents/{doc_id}/edit')
    assert edit_page_resp.status_code == 200

    # 2. Owner logs in and revokes the grant
    client.post('/auth/logout')
    client.post('/auth/login', data={'username': 'owner_def8', 'password': 'OwnerPassword123!'})
    revoke_resp = client.post(f'/documents/{doc_id}/sharing/{grant_id}/revoke', follow_redirects=True)
    assert revoke_resp.status_code == 200

    with app.app_context():
        g = db.session.get(AccessGrant, grant_id)
        assert g.revoked_at is not None
        assert g.is_active is False

    # 3. Viewer logs back in -> on the VERY NEXT request, editing is strictly rejected (403)
    client.post('/auth/logout')
    client.post('/auth/login', data={'username': 'viewer_def8', 'password': 'ViewerPassword123!'})

    # GET edit form returns 403 Forbidden
    assert client.get(f'/documents/{doc_id}/edit').status_code == 403

    # POST edit submission returns 403 Forbidden
    post_edit_resp = client.post(f'/documents/{doc_id}/edit', data={
        'title': 'Hacked Title After Revocation'
    })
    assert post_edit_resp.status_code == 403

    # Verify document in DB remained unaltered
    with app.app_context():
        d = db.session.get(Document, doc_id)
        assert d.title == "Design Specification"


# -----------------------------------------------------------------------------
# 9. Admin of Org A cannot view, change, or see audit entries of Org B
# -----------------------------------------------------------------------------

def test_cross_tenant_admin_isolation_documents_users_audit(client, app):
    """
    Threat: Cross-tenant data breach / privilege escalation across organization boundaries.
    Defense: All admin queries (audit_log, documents_list, users_list, toggle_user_status,
    change_user_role) explicitly enforce filter_by(org_id=current_user.org_id), preventing
    administrators of Org A from viewing, modifying, or querying anything belonging to Org B.
    """
    from app.audit import log_event

    with app.app_context():
        # Organization A (Alpha)
        org_a = Organization(name="Alpha Corp")
        db.session.add(org_a)
        db.session.flush()

        admin_a = User(org_id=org_a.id, username="admin_alpha", email="admin@alpha.org", role="admin")
        admin_a.set_password("AdminAlphaPass123!")

        user_a = User(org_id=org_a.id, username="worker_alpha", email="worker@alpha.org", role="viewer")
        user_a.set_password("WorkerAlphaPass123!")

        # Organization B (Beta)
        org_b = Organization(name="Beta Corp")
        db.session.add(org_b)
        db.session.flush()

        admin_b = User(org_id=org_b.id, username="admin_beta", email="admin@beta.org", role="admin")
        admin_b.set_password("AdminBetaPass123!")

        user_b = User(org_id=org_b.id, username="worker_beta", email="worker@beta.org", role="viewer", is_active=True)
        user_b.set_password("WorkerBetaPass123!")

        db.session.add_all([admin_a, user_a, admin_b, user_b])
        db.session.flush()

        # Documents in Org A and Org B
        doc_bytes = b"%PDF-1.4\nclean content"
        doc_a = Document(
            org_id=org_a.id,
            owner_id=admin_a.id,
            title="Alpha Public Strategy",
            filename="alpha.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="hash_a",
            data=doc_bytes
        )
        doc_b = Document(
            org_id=org_b.id,
            owner_id=admin_b.id,
            title="Beta Top Secret Roadmap",
            filename="beta_secret.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="hash_b",
            data=doc_bytes
        )
        db.session.add_all([doc_a, doc_b])
        db.session.flush()

        # Audit logs in Org A and Org B
        log_event(
            actor=admin_a,
            action="document.create",
            target_type="document",
            target_id=doc_a.id,
            outcome="allowed",
            detail="Alpha unique event: Project Apollo",
            org_id=org_a.id
        )
        log_event(
            actor=admin_b,
            action="document.create",
            target_type="document",
            target_id=doc_b.id,
            outcome="allowed",
            detail="Beta unique event: Project CyberZ",
            org_id=org_b.id
        )
        db.session.commit()

        doc_b_id = doc_b.id
        user_b_id = user_b.id

    # Admin of Org A logs in
    client.post('/auth/login', data={'username': 'admin_alpha', 'password': 'AdminAlphaPass123!'})

    # 1. Admin A CANNOT see audit entries of Org B
    audit_resp = client.get('/admin/audit')
    assert audit_resp.status_code == 200
    assert b"Alpha unique event: Project Apollo" in audit_resp.data
    assert b"Beta unique event: Project CyberZ" not in audit_resp.data

    # 2. Admin A CANNOT see Org B's documents in org repository
    org_docs_resp = client.get('/admin/documents')
    assert org_docs_resp.status_code == 200
    assert b"Alpha Public Strategy" in org_docs_resp.data
    assert b"Beta Top Secret Roadmap" not in org_docs_resp.data

    # Direct view or download of Doc B returns 404
    assert client.get(f'/documents/{doc_b_id}').status_code == 404
    assert client.get(f'/documents/{doc_b_id}/download').status_code == 404

    # 3. Admin A CANNOT see or modify users of Org B
    users_resp = client.get('/admin/users')
    assert users_resp.status_code == 200
    assert b"worker_alpha" in users_resp.data
    assert b"worker_beta" not in users_resp.data

    # Toggle status on User B returns 404
    toggle_resp = client.post(f'/admin/users/{user_b_id}/toggle-status')
    assert toggle_resp.status_code == 404

    # Change role on User B returns 404
    role_resp = client.post(f'/admin/users/{user_b_id}/change-role', data={'role': 'admin'})
    assert role_resp.status_code == 404

    # Verify User B was not modified
    with app.app_context():
        ub = db.session.get(User, user_b_id)
        assert ub.is_active is True
        assert ub.role == 'viewer'


# -----------------------------------------------------------------------------
# 10. Every state-changing route rejects GET requests (405 Method Not Allowed)
# -----------------------------------------------------------------------------

def test_every_state_changing_route_rejects_get(client, app):
    """
    Threat: Cross-Site Request Forgery (CSRF) or accidental triggering via prefetching,
    image tags, or link-clicking on state-changing actions using HTTP GET.
    Defense: All state-changing endpoints (logout, delete, grant, change permission,
    revoke, create user, toggle user status, change user role, verify audit chain)
    are strictly restricted to HTTP POST only (methods=['POST']) and return HTTP 405
    Method Not Allowed when targeted with HTTP GET requests.
    """
    with app.app_context():
        org = Organization(name="Defense Org 10")
        db.session.add(org)
        db.session.flush()

        admin = User(org_id=org.id, username="admin_def10", email="admin@def10.org", role="admin")
        admin.set_password("AdminPassword123!")
        db.session.add(admin)
        db.session.flush()

        doc_bytes = b"%PDF-1.4\ncontent"
        doc = Document(
            org_id=org.id,
            owner_id=admin.id,
            title="State Change Protected Doc",
            filename="protected.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256="dummyhash10",
            data=doc_bytes
        )
        db.session.add(doc)
        db.session.flush()

        grant = AccessGrant(
            document_id=doc.id,
            user_id=admin.id,
            permission='read',
            granted_by=admin.id
        )
        db.session.add(grant)
        db.session.commit()

        doc_id = doc.id
        grant_id = grant.id
        user_id = admin.id

    client.post('/auth/login', data={'username': 'admin_def10', 'password': 'AdminPassword123!'})

    # List of all dedicated state-changing endpoints
    state_changing_endpoints = [
        ('/auth/logout', "auth.logout"),
        (f'/documents/{doc_id}/delete', "documents.delete"),
        (f'/documents/{doc_id}/sharing/grant', "sharing.grant_access"),
        (f'/documents/{doc_id}/sharing/{grant_id}/change', "sharing.change_permission"),
        (f'/documents/{doc_id}/sharing/{grant_id}/revoke', "sharing.revoke_access"),
        ('/admin/users/create', "admin.create_user"),
        (f'/admin/users/{user_id}/toggle-status', "admin.toggle_user_status"),
        (f'/admin/users/{user_id}/change-role', "admin.change_user_role"),
        ('/admin/audit/verify', "admin.verify_audit_chain"),
    ]

    for url, endpoint_name in state_changing_endpoints:
        get_resp = client.get(url)
        assert get_resp.status_code == 405, f"Endpoint {endpoint_name} ({url}) did not reject GET with 405, got {get_resp.status_code}"









