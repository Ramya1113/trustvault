"""
Tests for authentication: registration, login, lockout, and session security.
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User
from app.blueprints.auth import clear_failed_attempts, is_account_locked
from config import Config


class AuthTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False  # Disabled in unit client to allow straightforward POST testing


@pytest.fixture
def app():
    """Create test application context with in-memory database."""
    app = create_app(AuthTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_registration_creates_org_and_admin(client, app):
    """
    Verify that registration:
    1. Creates a brand new Organization.
    2. Creates the user with role 'admin' belonging to that organization.
    3. Hashes the password with at least 10 characters.
    4. Automatically logs the user in.
    """
    response = client.post('/auth/register', data={
        'organization_name': 'Acme Industries',
        'username': 'acme_admin',
        'email': 'admin@acme.com',
        'password': 'SuperSecretPassword123!',
        'password_confirm': 'SuperSecretPassword123!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"created successfully!" in response.data
    assert b"Acme Industries" in response.data
    assert b"Role: Admin" in response.data

    with app.app_context():
        org = Organization.query.filter_by(name='Acme Industries').first()
        assert org is not None
        user = User.query.filter_by(username='acme_admin').first()
        assert user is not None
        assert user.org_id == org.id
        assert user.role == 'admin'
        assert user.check_password('SuperSecretPassword123!') is True


def test_registration_rejects_short_password(client, app):
    """Verify that passwords shorter than 10 characters are rejected."""
    client.post('/auth/logout')  # Ensure client is unauthenticated
    response = client.post('/auth/register', data={
        'organization_name': 'Beta Corp',
        'username': 'beta_admin',
        'email': 'admin@beta.com',
        'password': 'short',
        'password_confirm': 'short'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Password must be at least 10 characters long" in response.data

    with app.app_context():
        assert User.query.filter_by(username='beta_admin').first() is None
        assert Organization.query.filter_by(name='Beta Corp').first() is None


def test_registration_rejects_duplicate_org_or_username(client):
    """Verify unique organization names and usernames."""
    client.post('/auth/logout')  # Ensure unauthenticated

    # First registration
    client.post('/auth/register', data={
        'organization_name': 'Unique Org',
        'username': 'unique_user',
        'email': 'unique@example.com',
        'password': 'ValidPassword123!',
        'password_confirm': 'ValidPassword123!'
    }, follow_redirects=True)

    # Log out to test registration form validation as a guest
    client.post('/auth/logout')

    # Second registration with duplicate org
    resp1 = client.post('/auth/register', data={
        'organization_name': 'Unique Org',
        'username': 'other_user',
        'email': 'other@example.com',
        'password': 'ValidPassword123!',
        'password_confirm': 'ValidPassword123!'
    }, follow_redirects=True)
    assert b"An organization with this name already exists" in resp1.data

    # Third registration with duplicate username
    resp2 = client.post('/auth/register', data={
        'organization_name': 'Another Org',
        'username': 'unique_user',
        'email': 'different@example.com',
        'password': 'ValidPassword123!',
        'password_confirm': 'ValidPassword123!'
    }, follow_redirects=True)
    assert b"This username is already taken" in resp2.data


def test_login_generic_error_message(client, app):
    """
    Verify generic error message on bad login:
    Does NOT reveal whether the username exists or not.
    """
    # Create test user
    with app.app_context():
        org = Organization(name="Gamma Org")
        db.session.add(org)
        db.session.commit()
        user = User(org_id=org.id, username="gamma_user", email="gamma@example.com", role="viewer")
        user.set_password("CorrectPassword123!")
        db.session.add(user)
        db.session.commit()

    clear_failed_attempts("gamma_user")
    clear_failed_attempts("nonexistent_user")

    # 1. Existing user, bad password
    resp1 = client.post('/auth/login', data={
        'username': 'gamma_user',
        'password': 'WrongPassword999!'
    }, follow_redirects=True)
    assert b"Invalid username or password." in resp1.data

    # 2. Non-existent user
    resp2 = client.post('/auth/login', data={
        'username': 'nonexistent_user',
        'password': 'AnyPassword123!'
    }, follow_redirects=True)
    assert b"Invalid username or password." in resp2.data

    # Both return the exact same generic error message!


def test_login_lockout_after_five_failed_attempts(client, app):
    """
    Verify rate limiting locks out a username after 5 failed attempts for 10 minutes.
    """
    test_user = "lockout_test_user"
    clear_failed_attempts(test_user)

    with app.app_context():
        org = Organization(name="Lockout Org")
        db.session.add(org)
        db.session.commit()
        user = User(org_id=org.id, username=test_user, email="lock@example.com", role="viewer")
        user.set_password("GoodPassword123!")
        db.session.add(user)
        db.session.commit()

    # 5 failed login attempts
    for i in range(5):
        resp = client.post('/auth/login', data={
            'username': test_user,
            'password': 'BadPassword!'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid username or password." in resp.data

    # 6th attempt should be locked out
    resp_locked = client.post('/auth/login', data={
        'username': test_user,
        'password': 'GoodPassword123!'
    }, follow_redirects=True)
    assert resp_locked.status_code == 429
    assert b"Account temporarily locked due to too many failed login attempts" in resp_locked.data

    # Cleanup
    clear_failed_attempts(test_user)


def test_successful_login_and_logout(client, app):
    """Verify login and logout session flows."""
    with app.app_context():
        org = Organization(name="Session Org")
        db.session.add(org)
        db.session.commit()
        user = User(org_id=org.id, username="session_user", email="session@example.com", role="owner")
        user.set_password("SessionPass123!")
        db.session.add(user)
        db.session.commit()

    clear_failed_attempts("session_user")

    # Login
    resp = client.post('/auth/login', data={
        'username': 'session_user',
        'password': 'SessionPass123!'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Signed in successfully." in resp.data
    assert b"session_user (Session Org)" in resp.data

    # Logout
    logout_resp = client.post('/auth/logout', follow_redirects=True)
    assert logout_resp.status_code == 200

    assert b"You have been signed out." in logout_resp.data
    assert b"Sign In" in logout_resp.data


def test_session_cookie_flags(app):
    """Verify session cookie security flags in configuration."""
    assert app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
