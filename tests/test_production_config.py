"""
Tests for Production Configuration & Error Handling (Item 1):
- DEBUG is False by default
- SECRET_KEY only from env on Render (fails if missing)
- SESSION_COOKIE_SECURE=True when running on Render
- Custom 403, 404, and 500 error pages without stack traces
"""
import os
import pytest
from app import create_app
from config import Config


class DevConfig(Config):
    """Standard dev config for testing."""
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


def test_debug_off_by_default():
    """Verify that DEBUG is False by default in Config and created app."""
    assert Config.DEBUG is False
    app = create_app(DevConfig)
    assert app.config['DEBUG'] is False


def test_render_secret_key_required(monkeypatch):
    """Verify that on Render, create_app raises ValueError if SECRET_KEY is missing."""
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.delenv('SECRET_KEY', raising=False)

    class RenderMissingSecretConfig(Config):
        TESTING = False
        SECRET_KEY = None

    with pytest.raises(ValueError, match="SECRET_KEY environment variable must be set"):
        create_app(RenderMissingSecretConfig)


def test_render_session_cookie_secure(monkeypatch):
    """Verify that SESSION_COOKIE_SECURE and REMEMBER_COOKIE_SECURE are True on Render."""
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.setenv('SECRET_KEY', 'render-test-secret-key-12345')

    class RenderConfig(Config):
        TESTING = False
        SECRET_KEY = 'render-test-secret-key-12345'
        SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        WTF_CSRF_ENABLED = False

    app = create_app(RenderConfig)
    assert app.config['SESSION_COOKIE_SECURE'] is True
    assert app.config['REMEMBER_COOKIE_SECURE'] is True


def test_custom_404_error_page():
    """Verify that accessing a nonexistent URL returns custom 404 page without stack trace."""
    app = create_app(DevConfig)
    client = app.test_client()
    response = client.get('/nonexistent-page-url-12345')
    assert response.status_code == 404
    html = response.get_data(as_text=True)
    assert 'Page Not Found' in html
    assert '404' in html
    assert 'Traceback' not in html
    assert 'File "' not in html


def test_custom_403_error_page():
    """Verify that an aborted 403 returns custom 403 page without stack trace."""
    from flask import abort
    app = create_app(DevConfig)

    @app.route('/test-403-trigger')
    def trigger_403():
        abort(403)

    client = app.test_client()
    response = client.get('/test-403-trigger')
    assert response.status_code == 403
    html = response.get_data(as_text=True)
    assert 'Access Forbidden' in html
    assert '403' in html
    assert 'Traceback' not in html


def test_custom_500_error_page():
    """Verify that an unhandled 500 returns custom 500 page without stack trace."""
    app = create_app(DevConfig)
    # Ensure exceptions are caught by error handlers instead of re-raised
    app.config['TRAP_HTTP_EXCEPTIONS'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = False

    @app.route('/test-500-trigger')
    def trigger_500():
        raise RuntimeError("Unexpected simulated failure")

    client = app.test_client()
    response = client.get('/test-500-trigger')
    assert response.status_code == 500
    html = response.get_data(as_text=True)
    assert 'Internal Server Error' in html
    assert '500' in html
    assert 'Traceback' not in html
    assert 'Unexpected simulated failure' not in html
