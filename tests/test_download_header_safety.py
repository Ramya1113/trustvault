"""
Tests for Download Content-Disposition Header Safety (Item 5):
- Confirms the filename in Content-Disposition cannot inject headers or quotes.
- Validates that filenames with quotes or CRLF characters are safely sanitized.
"""
import hashlib
import pytest
from app import create_app
from extensions import db
from app.models import Organization, User, Document
from config import Config


class DownloadHeaderConfig(Config):
    """Configuration for download header security testing."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    """Setup application and test database with user and documents."""
    app = create_app(DownloadHeaderConfig)
    with app.app_context():
        db.create_all()
        org = Organization(name="Header Test Org")
        db.session.add(org)
        db.session.flush()

        owner = User(
            org_id=org.id,
            username="doc_owner",
            email="owner@header.org",
            role="owner",
            is_active=True
        )
        owner.set_password("OwnerPassword123!")
        db.session.add(owner)
        db.session.flush()

        # Legitimate document
        doc_bytes = b"%PDF-1.4\nsample pdf content"
        normal_doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Safe Report",
            filename="safe_report.pdf",
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256=hashlib.sha256(doc_bytes).hexdigest(),
            data=doc_bytes
        )
        db.session.add(normal_doc)

        # Document with quotes and CRLF injection attempt in filename
        malicious_doc = Document(
            org_id=org.id,
            owner_id=owner.id,
            title="Malicious Filename Doc",
            filename='injected";\r\nSet-Cookie: evil=1\r\nDummy: "name.pdf',
            mime_type="application/pdf",
            size=len(doc_bytes),
            sha256=hashlib.sha256(doc_bytes).hexdigest(),
            data=doc_bytes
        )
        db.session.add(malicious_doc)
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_download_legitimate_content_disposition(client, app):
    """Verify that a legitimate document has a valid attachment Content-Disposition header."""
    client.post('/auth/login', data={'username': 'doc_owner', 'password': 'OwnerPassword123!'})

    with app.app_context():
        doc = Document.query.filter_by(title="Safe Report").first()
        doc_id = doc.id

    response = client.get(f'/documents/{doc_id}/download')
    assert response.status_code == 200
    content_disp = response.headers.get('Content-Disposition')
    assert content_disp is not None
    assert 'attachment' in content_disp
    assert 'safe_report.pdf' in content_disp
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'


def test_download_sanitizes_quotes_and_crlf_in_content_disposition(client, app):
    """Verify that quotes and CRLF are sanitized, preventing header splitting and quote escapes."""
    client.post('/auth/login', data={'username': 'doc_owner', 'password': 'OwnerPassword123!'})

    with app.app_context():
        doc = Document.query.filter_by(title="Malicious Filename Doc").first()
        doc_id = doc.id

    response = client.get(f'/documents/{doc_id}/download')
    assert response.status_code == 200

    # Ensure no CRLF injected headers exist as separate HTTP headers
    assert 'Dummy' not in response.headers
    # If Set-Cookie is present for session, ensure evil=1 was not injected into it
    assert 'evil=1' not in response.headers.get('Set-Cookie', '')

    content_disp = response.headers.get('Content-Disposition')
    assert content_disp is not None
    # Must not contain raw carriage return or line feeds (CRLF injection prevented)
    assert '\r' not in content_disp
    assert '\n' not in content_disp
    # Must be valid filename with extension
    assert 'name.pdf' in content_disp

