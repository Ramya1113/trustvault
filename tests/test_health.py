"""
Tests for application initialization and the /healthz health check route.
"""
import pytest
from app import create_app
from config import Config


class TestConfig(Config):
    """Test configuration setting testing mode and memory/temp SQLite."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Create and configure a testing Flask application instance."""
    app = create_app(TestConfig)
    return app


@pytest.fixture
def client(app):
    """Create a test client for sending HTTP requests."""
    return app.test_client()


def test_healthz_route(client):
    """Verify that /healthz returns status 200 OK and expected JSON payload."""
    response = client.get('/healthz')
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert data == {'status': 'ok'}


def test_max_content_length(app):
    """Verify that the maximum content upload length is 5 MB."""
    assert app.config['MAX_CONTENT_LENGTH'] == 5 * 1024 * 1024


def test_base_template_renders(app):
    """Verify that base.html renders cleanly without Jinja template syntax errors."""
    from flask import render_template
    with app.test_request_context():
        rendered = render_template('base.html')
        assert 'TrustVault' in rendered
        assert 'Tenant Secure' in rendered
        assert '/healthz' in rendered
