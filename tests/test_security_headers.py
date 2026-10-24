"""
Tests for Defensive HTTP Security Headers (Item 2):
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin
- Content-Security-Policy: basic CSP restricting sources
"""
import pytest
from app import create_app
from config import Config


class SecurityHeadersConfig(Config):
    """Configuration for testing security headers."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def client():
    """Create test client with security headers configuration."""
    app = create_app(SecurityHeadersConfig)
    return app.test_client()


def test_security_headers_on_standard_endpoint(client):
    """Verify security headers are present on regular 200 OK responses."""
    response = client.get('/healthz')
    assert response.status_code == 200

    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    csp = response.headers.get('Content-Security-Policy')
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_on_html_page(client):
    """Verify security headers are present on HTML pages such as login."""
    response = client.get('/auth/login')
    assert response.status_code == 200

    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    csp = response.headers.get('Content-Security-Policy')
    assert csp is not None
    assert "default-src 'self'" in csp


def test_security_headers_on_redirect(client):
    """Verify security headers are present even on 302 redirect responses."""
    response = client.get('/')
    assert response.status_code == 302

    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'Content-Security-Policy' in response.headers


def test_security_headers_on_404_error(client):
    """Verify security headers are present on 404 error responses."""
    response = client.get('/nonexistent-url-security-header-check')
    assert response.status_code == 404

    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'Content-Security-Policy' in response.headers
