"""
Tests for Role/Org Form Tampering and Account Enumeration Defense (Item 4):
- Registration ignores role and org_id fields submitted by the client (role is admin, org is new org).
- User creation ignores org_id fields submitted by the client (bound to admin's org_id).
- User creation rejects invalid role values not in choices.
- Login returns identical generic error messages for valid and invalid usernames.
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User
from config import Config


class TamperTestConfig(Config):
    """Configuration for form tampering tests."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Application fixture with test database."""
    app = create_app(TamperTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_registration_tampered_role_and_org_ignored(client, app):
    """
    Verify that an attacker attempting to pass role='superadmin' or org_id=999
    in registration form data cannot hijack another org or assign arbitrary roles.
    """
    client.post('/auth/register', data={
        'organization_name': 'Tamper Test Org',
        'username': 'tamper_user',
        'email': 'tamper@test.org',
        'password': 'SecurePassword123!',
        'password_confirm': 'SecurePassword123!',
        # Attacker injects tampering fields:
        'role': 'superadmin',
        'org_id': 999
    }, follow_redirects=True)

    with app.app_context():
        user = User.query.filter_by(username='tamper_user').first()
        org = Organization.query.filter_by(name='Tamper Test Org').first()

        assert user is not None
        assert org is not None
        # Must be admin of their own new organization, NOT org_id 999
        assert user.org_id == org.id
        assert user.org_id != 999
        assert user.role == 'admin'


def test_create_user_tampered_org_id_ignored(client, app):
    """
    Verify that an administrator creating a user cannot assign them to another org_id
    by tampering with form fields.
    """
    with app.app_context():
        org1 = Organization(name="Admin Org 1")
        org2 = Organization(name="Target Org 2")
        db.session.add_all([org1, org2])
        db.session.commit()
        org1_id = org1.id
        org2_id = org2.id

        admin = User(org_id=org1_id, username="admin1", email="admin1@test.org", role="admin")
        admin.set_password("AdminPass123!")
        db.session.add(admin)
        db.session.commit()

    # Log in as admin1
    client.post('/auth/login', data={'username': 'admin1', 'password': 'AdminPass123!'})

    # Admin attempts to create a user in Target Org 2 by submitting org_id=org2_id
    client.post('/admin/users/create', data={
        'username': 'created_colleague',
        'email': 'colleague@test.org',
        'password': 'ColleaguePass123!',
        'role': 'viewer',
        'org_id': org2_id  # Tampered field
    }, follow_redirects=True)

    with app.app_context():
        created = User.query.filter_by(username='created_colleague').first()
        assert created is not None
        # Must belong to org1 (admin's org), never org2
        assert created.org_id == org1_id
        assert created.org_id != org2_id



def test_create_user_invalid_role_rejected(client, app):
    """
    Verify that submitting an unrecognized role (e.g. 'root' or 'superadmin')
    fails form validation and does not create the user.
    """
    with app.app_context():
        org = Organization(name="Role Org")
        db.session.add(org)
        db.session.commit()

        admin = User(org_id=org.id, username="role_admin", email="admin@role.org", role="admin")
        admin.set_password("AdminPass123!")
        db.session.add(admin)
        db.session.commit()

    client.post('/auth/login', data={'username': 'role_admin', 'password': 'AdminPass123!'})

    resp = client.post('/admin/users/create', data={
        'username': 'bad_role_user',
        'email': 'badrole@role.org',
        'password': 'BadRolePass123!',
        'role': 'superadmin'
    }, follow_redirects=True)

    with app.app_context():
        assert User.query.filter_by(username='bad_role_user').first() is None


def test_login_does_not_enumerate_usernames(client, app):
    """
    Verify that login returns identical error messaging for an existing user with bad password
    and a non-existent user.
    """
    with app.app_context():
        org = Organization(name="Enum Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="existing_account", email="exist@enum.org", role="viewer")
        user.set_password("CorrectPassword123!")
        db.session.add(user)
        db.session.commit()

    # Existing user, wrong password
    resp1 = client.post('/auth/login', data={
        'username': 'existing_account',
        'password': 'WrongPassword123!'
    }, follow_redirects=True)

    # Non-existent user
    resp2 = client.post('/auth/login', data={
        'username': 'non_existent_account',
        'password': 'WrongPassword123!'
    }, follow_redirects=True)

    assert b"Invalid username or password" in resp1.data
    assert b"Invalid username or password" in resp2.data
    # Ensure neither response discloses account existence
    assert b"User not found" not in resp2.data
    assert b"Incorrect password" not in resp1.data
