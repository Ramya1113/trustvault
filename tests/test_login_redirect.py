"""
Tests for Safe Login Redirect & Open Redirect Prevention (Item 3):
- Relative paths on the same site are allowed (e.g. /documents).
- Protocol-relative URLs (//evil.com, /\\evil.com) are rejected.
- External URLs (http://attacker.com, https://phishing.site) are rejected.
- In all rejected cases, the application falls back safely to the dashboard.
"""
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User
from app.blueprints.auth import is_safe_redirect_url
from config import Config


class RedirectTestConfig(Config):
    """Configuration for login redirect testing."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Setup application and test database."""
    app = create_app(RedirectTestConfig)
    with app.app_context():
        db.create_all()
        org = Organization(name="Redirect Corp")
        db.session.add(org)
        db.session.flush()

        user = User(
            org_id=org.id,
            username="redirect_user",
            email="user@redirect.corp",
            role="owner",
            is_active=True
        )
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_is_safe_redirect_url_unit():
    """Direct unit tests for is_safe_redirect_url validator."""
    # Safe paths
    assert is_safe_redirect_url('/documents') is True
    assert is_safe_redirect_url('/documents/1/download') is True
    assert is_safe_redirect_url('/auth/dashboard') is True

    # Unsafe / open redirect attempts
    assert is_safe_redirect_url(None) is False
    assert is_safe_redirect_url('') is False
    assert is_safe_redirect_url('http://evil.com') is False
    assert is_safe_redirect_url('https://evil.com') is False
    assert is_safe_redirect_url('//evil.com') is False
    assert is_safe_redirect_url('//evil.com/documents') is False
    assert is_safe_redirect_url('/\\evil.com') is False
    assert is_safe_redirect_url('\\evil.com') is False
    assert is_safe_redirect_url('javascript:alert(1)') is False
    assert is_safe_redirect_url('ftp://evil.com') is False


def test_login_redirect_allowed_for_relative_url(client):
    """Verify that a legitimate relative URL in next is respected."""
    response = client.post('/auth/login?next=/documents', data={
        'username': 'redirect_user',
        'password': 'SecurePassword123!'
    }, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers['Location'] == '/documents'


@pytest.mark.parametrize("malicious_target", [
    "http://evil.com",
    "https://evil.com/phish",
    "//evil.com",
    "//evil.com/steal-creds",
    "/\\evil.com",
    "javascript:alert(1)",
])
def test_login_rejects_open_redirect_and_defaults_to_dashboard(client, malicious_target):
    """Verify that any open redirect attempt is blocked and sent to the dashboard."""
    response = client.post(f'/auth/login?next={malicious_target}', data={
        'username': 'redirect_user',
        'password': 'SecurePassword123!'
    }, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers['Location'] == '/auth/dashboard'
