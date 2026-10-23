"""
Application factory module for TrustVault.

This module initializes and configures the Flask application instance using
the application factory pattern (create_app).
"""
import os
import click
from flask import Flask, jsonify
from config import Config
from extensions import db, login_manager, csrf


def create_app(config_class=Config):
    """
    Create and configure an instance of the Flask application.

    Args:
        config_class: Configuration class containing application settings.
                      Defaults to Config from config.py.

    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions with the application instance
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # User loader for Flask-Login session management
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        try:
            return db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None

    # Configure Flask-Login defaults
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Please sign in to access this page."
    login_manager.login_message_category = "info"

    # Register blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.documents import docs_bp
    from app.blueprints.sharing import sharing_bp
    from app.blueprints.admin import admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(sharing_bp)
    app.register_blueprint(admin_bp)

    # CLI command: flask init-db
    @app.cli.command('init-db')
    def init_db():
        """Initialize database by creating all model tables."""
        from app import models  # noqa: F401
        db.create_all()
        click.echo("Initialized database tables successfully.")

    # Root route: redirects to dashboard if authenticated, or login if guest
    @app.route('/')
    def index():
        from flask_login import current_user
        from flask import redirect, url_for
        if current_user.is_authenticated:
            return redirect(url_for('auth.dashboard'))
        return redirect(url_for('auth.login'))

    # Health check route for uptime monitoring, Docker/container health checks, and load balancers
    @app.route('/healthz', methods=['GET'])
    def healthz():
        """
        Health check endpoint.
        Returns HTTP 200 OK with a simple JSON status payload.
        """
        return jsonify(status="ok"), 200

    return app
