"""
Configuration module for TrustVault.

This module reads application settings (such as SECRET_KEY and DATABASE_URL)
from environment variables. If DATABASE_URL is not provided, it defaults
to a local SQLite database stored in the instance/ folder.
"""
import os

# Base directory of the project repository
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Application configuration with environment-driven variables and safe defaults."""

    # Secret key used for cryptographic signing of session cookies and CSRF tokens.
    # In production, this must be set securely via the SECRET_KEY environment variable.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-secret-key-change-in-production')

    # Database connection URI:
    # Uses DATABASE_URL from the environment if set (e.g., PostgreSQL in production).
    # Otherwise, falls back to a local SQLite database inside the instance/ directory.
    _database_url = os.environ.get('DATABASE_URL')

    if _database_url:
        # Some cloud providers (like Heroku) provide 'postgres://', but SQLAlchemy requires 'postgresql://'
        if _database_url.startswith('postgres://'):
            _database_url = _database_url.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = _database_url
    else:
        # Default to local SQLite database in instance/
        instance_dir = os.path.join(BASE_DIR, 'instance')
        os.makedirs(instance_dir, exist_ok=True)
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(instance_dir, 'trustvault.db')}"

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
