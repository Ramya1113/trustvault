"""
Flask extensions module.

Extensions are instantiated here without binding to a specific Flask app.
They will be initialized in the application factory (create_app in app/__init__.py).
This pattern prevents circular dependencies when importing models or routes.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# Database ORM instance
db = SQLAlchemy()

# Authentication and session manager instance
login_manager = LoginManager()

# Cross-Site Request Forgery (CSRF) protection instance
csrf = CSRFProtect()
