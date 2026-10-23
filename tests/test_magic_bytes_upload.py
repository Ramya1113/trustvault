"""
Integration tests for Issue 5:
- secure_filename handling
- Authoritative extension-to-MIME mapping
- Magic-byte validation for PDF, PNG, and JPG/JPEG
"""

import io
import pytest
from app import create_app
from config import Config
from extensions import db
from app.models import Organization, User, Document
from app.blueprints.documents import EXTENSION_MIME_MAP


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def test_setup():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()

        org = Organization(name="MagicBytes Org")
        db.session.add(org)
        db.session.commit()

        owner = User(
            org_id=org.id,
            username="docowner",
            email="docowner@example.com",
            role="owner",
            is_active=True
        )
        owner.set_password("Password123!")
        db.session.add(owner)
        db.session.commit()

        yield app, org, owner
        db.session.remove()
        db.drop_all()


def test_magic_bytes_valid_pdf_png_jpg(test_setup):
    """Valid PDF, PNG, and JPG files pass magic-byte checks and get authoritative MIME type."""
    app, org, owner = test_setup
    client = app.test_client()

    # Login as owner
    client.post('/auth/login', data={'username': 'docowner', 'password': 'Password123!'})

    # 1. Valid PDF
    valid_pdf_content = b"%PDF-1.4\n%Fake PDF binary stream..."
    resp = client.post('/documents/upload', data={
        'title': 'Valid PDF Doc',
        'description': 'Real PDF',
        'file': (io.BytesIO(valid_pdf_content), 'report.pdf')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"uploaded successfully" in resp.data

    with app.app_context():
        doc = Document.query.filter_by(title='Valid PDF Doc').first()
        assert doc is not None
        assert doc.mime_type == EXTENSION_MIME_MAP['pdf']
        assert doc.mime_type == 'application/pdf'

    # 2. Valid PNG
    valid_png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."
    resp = client.post('/documents/upload', data={
        'title': 'Valid PNG Doc',
        'description': 'Real PNG',
        'file': (io.BytesIO(valid_png_content), 'chart.png')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"uploaded successfully" in resp.data

    with app.app_context():
        doc = Document.query.filter_by(title='Valid PNG Doc').first()
        assert doc is not None
        assert doc.mime_type == EXTENSION_MIME_MAP['png']
        assert doc.mime_type == 'image/png'

    # 3. Valid JPG
    valid_jpg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF..."
    resp = client.post('/documents/upload', data={
        'title': 'Valid JPG Doc',
        'description': 'Real JPG',
        'file': (io.BytesIO(valid_jpg_content), 'photo.jpg')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"uploaded successfully" in resp.data

    with app.app_context():
        doc = Document.query.filter_by(title='Valid JPG Doc').first()
        assert doc is not None
        assert doc.mime_type == EXTENSION_MIME_MAP['jpg']
        assert doc.mime_type == 'image/jpeg'


def test_magic_bytes_spoofing_rejected(test_setup):
    """Spoofed files (e.g. plain text or binary disguised as PDF/PNG/JPG) are rejected."""
    app, org, owner = test_setup
    client = app.test_client()

    client.post('/auth/login', data={'username': 'docowner', 'password': 'Password123!'})

    # Spoofed PDF (plain text content)
    fake_pdf = b"Hello, this is just plain text masquerading as a PDF."
    resp = client.post('/documents/upload', data={
        'title': 'Spoofed PDF',
        'description': 'Fake PDF',
        'file': (io.BytesIO(fake_pdf), 'spoof.pdf')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"File contents do not match extension (invalid file signature)." in resp.data

    # Spoofed PNG
    fake_png = b"Not a PNG image file header"
    resp = client.post('/documents/upload', data={
        'title': 'Spoofed PNG',
        'description': 'Fake PNG',
        'file': (io.BytesIO(fake_png), 'spoof.png')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"File contents do not match extension (invalid file signature)." in resp.data

    # Spoofed JPG
    fake_jpg = b"Not a JPG image file header"
    resp = client.post('/documents/upload', data={
        'title': 'Spoofed JPG',
        'description': 'Fake JPG',
        'file': (io.BytesIO(fake_jpg), 'spoof.jpg')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"File contents do not match extension (invalid file signature)." in resp.data

    # Ensure none of these fake documents were saved
    with app.app_context():
        assert Document.query.filter_by(title='Spoofed PDF').first() is None
        assert Document.query.filter_by(title='Spoofed PNG').first() is None
        assert Document.query.filter_by(title='Spoofed JPG').first() is None


def test_magic_bytes_spoofing_rejected_on_edit(test_setup):
    """Uploading a spoofed file on document edit/version update is also rejected."""
    app, org, owner = test_setup
    client = app.test_client()

    client.post('/auth/login', data={'username': 'docowner', 'password': 'Password123!'})

    # Upload valid document first
    valid_pdf_content = b"%PDF-1.4\nInitial content"
    client.post('/documents/upload', data={
        'title': 'Original Doc',
        'description': 'Initial',
        'file': (io.BytesIO(valid_pdf_content), 'orig.pdf')
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(title='Original Doc').first()
        doc_id = doc.id
        assert doc.version == 1

    # Attempt to update with a fake PDF
    fake_pdf = b"Corrupted fake PDF bytes"
    resp = client.post(f'/documents/{doc_id}/edit', data={
        'title': 'Updated Title',
        'description': 'Updated Desc',
        'file': (io.BytesIO(fake_pdf), 'new_version.pdf')
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"File contents do not match extension (invalid file signature)." in resp.data

    # Verify version was NOT bumped and file content was NOT overwritten
    with app.app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.version == 1
        assert doc.data == valid_pdf_content


def test_secure_filename_applied(test_setup):
    """Filename path traversals and dangerous characters are sanitized by secure_filename."""
    app, org, owner = test_setup
    client = app.test_client()

    client.post('/auth/login', data={'username': 'docowner', 'password': 'Password123!'})

    valid_pdf = b"%PDF-1.4\nSome safe PDF"
    resp = client.post('/documents/upload', data={
        'title': 'Traversal Test',
        'file': (io.BytesIO(valid_pdf), '../../../etc/passwd.pdf')
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        doc = Document.query.filter_by(title='Traversal Test').first()
        assert doc is not None
        assert '/' not in doc.filename
        assert '\\' not in doc.filename
        assert doc.filename == 'etc_passwd.pdf'
