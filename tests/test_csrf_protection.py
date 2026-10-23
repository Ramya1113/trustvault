"""
Test for Issue 4: CSRF protection enabled.
Verifies that:
- State-changing POST requests without a CSRF token return HTTP 400 Bad Request.
- POST requests with an invalid CSRF token return HTTP 400 Bad Request.
- POST requests with a valid extracted CSRF token are accepted.
"""
import re
import pytest
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User


class CsrfEnabledTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = True  # Explicitly enable CSRF protection


@pytest.fixture
def app():
    app = create_app(CsrfEnabledTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_post_without_csrf_token_returns_400(client):
    """Confirm POST without CSRF token is rejected with HTTP 400 Bad Request."""
    resp = client.post('/auth/login', data={
        'username': 'some_user',
        'password': 'SomePassword123!'
    })

    assert resp.status_code == 400
    assert b"CSRF" in resp.data or b"The CSRF token is missing" in resp.data or b"Bad Request" in resp.data


def test_post_with_invalid_csrf_token_returns_400(client):
    """Confirm POST with a forged or invalid CSRF token returns HTTP 400 Bad Request."""
    resp = client.post('/auth/login', data={
        'csrf_token': 'forged_or_invalid_token_xyz',
        'username': 'some_user',
        'password': 'SomePassword123!'
    })

    assert resp.status_code == 400
    assert b"CSRF" in resp.data or b"The CSRF token is invalid" in resp.data or b"Bad Request" in resp.data


def test_post_with_valid_csrf_token_is_accepted(client, app):
    """Confirm POST with a legitimate CSRF token succeeds."""
    with app.app_context():
        org = Organization(name="CSRF Test Org")
        db.session.add(org)
        db.session.commit()

        user = User(org_id=org.id, username="csrf_user", email="csrf@example.com", role="owner")
        user.set_password("ValidPassword123!")
        db.session.add(user)
        db.session.commit()

    # 1. Fetch login form to obtain session cookie and rendered CSRF token
    get_resp = client.get('/auth/login')
    assert get_resp.status_code == 200

    match = re.search(r'name="csrf_token".*?value="([^"]+)"', get_resp.data.decode('utf-8'))
    assert match is not None, "CSRF token input field not found in rendered HTML"
    valid_csrf_token = match.group(1)

    # 2. Submit POST with valid token
    post_resp = client.post('/auth/login', data={
        'csrf_token': valid_csrf_token,
        'username': 'csrf_user',
        'password': 'ValidPassword123!'
    }, follow_redirects=True)

    # Legitimate CSRF token was accepted -> login succeeded and redirected
    assert post_resp.status_code == 200
    assert b"Welcome back" in post_resp.data or b"Dashboard" in post_resp.data
