"""
Re-export extensions for convenient intra-package access (from app.extensions import db).
"""
from extensions import db, login_manager, csrf

__all__ = ['db', 'login_manager', 'csrf']
