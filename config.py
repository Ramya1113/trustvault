"""
Configuration module for TrustVault.

This module reads application settings (such as SECRET_KEY and DATABASE_URL)
from environment variables. If DATABASE_URL is not provided, it defaults
to a local SQLite database stored in the instance/ folder.

Render/Heroku Compatibility:
Render PostgreSQL instances frequently inject DATABASE_URL starting with 'postgres://'.
SQLAlchemy 2+ requires the dialect prefix 'postgresql://'. This module transparently
normalizes 'postgres://' to 'postgresql://'.
"""
import os

# Base directory of the project repository
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def get_database_uri():
    """
    Retrieve and normalize the database connection URI from the environment.
    Converts legacy 'postgres://' schemes provided by cloud hosts to 'postgresql://'.
    Falls back to a local SQLite database in instance/ for development.
    """
    url = os.environ.get('DATABASE_URL')
    if url:
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        return url

    # Default to local SQLite database in instance/
    instance_dir = os.path.join(BASE_DIR, 'instance')
    os.makedirs(instance_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(instance_dir, 'trustvault.db')}"


class Config:
    """Application configuration with environment-driven variables and safe defaults."""

    # Secret key used for cryptographic signing of session cookies and CSRF tokens.
    # On Render, set via environment variable SECRET_KEY.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-secret-key-change-in-production')

    # Database connection URI
    SQLALCHEMY_DATABASE_URI = get_database_uri()

    # Disable SQLAlchemy event system modification tracking to conserve memory
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Maximum allowed payload size for file uploads: 5 MB (in bytes)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    # Session cookie security flags
    # HttpOnly prevents client-side scripts from accessing cookies, mitigating XSS risks.
    # SameSite=Lax prevents CSRF in cross-site requests while preserving top-level navigation.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
