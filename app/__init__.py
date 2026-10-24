"""
Application factory module for TrustVault.

This module initializes and configures the Flask application instance using
the application factory pattern (create_app).
"""
import os
import hashlib
from datetime import datetime, timezone
import click
from flask import Flask, jsonify, redirect, render_template, url_for
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

    # Ensure SECRET_KEY from environment is applied
    env_secret = os.environ.get('SECRET_KEY')
    if env_secret:
        app.config['SECRET_KEY'] = env_secret
    elif os.environ.get('RENDER') and not app.config.get('TESTING'):
        raise ValueError("SECRET_KEY environment variable must be set when running on Render")

    # Enforce cookie security flags when running on Render
    if os.environ.get('RENDER'):
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['REMEMBER_COOKIE_SECURE'] = True


    # Ensure DATABASE_URL from environment is applied with postgresql:// dialect fix
    env_db_url = os.environ.get('DATABASE_URL')
    if env_db_url:
        if env_db_url.startswith('postgres://'):
            env_db_url = env_db_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = env_db_url

    # Initialize extensions with the application instance
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # User loader for Flask-Login session management
    # Security Rule: If a user is deactivated, immediately return None so their existing
    # session cookie is invalidated on the very next request.
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        try:
            user = db.session.get(User, int(user_id))
            if user is not None and not user.is_active:
                return None
            return user

        except (ValueError, TypeError):
            return None


    @app.before_request
    def enforce_active_session():
        from flask_login import current_user, logout_user
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            return redirect(url_for('auth.login'))


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

    # CLI command: flask seed-db (and alias flask seed)
    def _execute_seed(print_banner=True):
        """Creates a demo organization with one admin, one owner, one viewer, and prints credentials."""
        from app.models import Organization, User, Document, AccessGrant
        from app.audit import log_event

        db.create_all()

        demo_org_name = "Acme Corporation"
        org = Organization.query.filter_by(name=demo_org_name).first()

        if org is None:
            org = Organization(name=demo_org_name)
            db.session.add(org)
            db.session.flush()

        # Demo credentials dictionary
        demo_accounts = [
            {
                'role': 'admin',
                'username': 'demo_admin',
                'email': 'admin@acme.demo',
                'password': 'AdminPassword123!',
                'description': 'Full tenant administration, user management, and audit inspection'
            },
            {
                'role': 'owner',
                'username': 'demo_owner',
                'email': 'owner@acme.demo',
                'password': 'OwnerPassword123!',
                'description': 'Uploads documents and delegates read/edit sharing permissions'
            },
            {
                'role': 'viewer',
                'username': 'demo_viewer',
                'email': 'viewer@acme.demo',
                'password': 'ViewerPassword123!',
                'description': 'Read-only access strictly to documents explicitly shared with them'
            }
        ]

        created_users = {}

        for acc in demo_accounts:
            user = User.query.filter_by(username=acc['username']).first()
            if user is None:
                user = User(
                    org_id=org.id,
                    username=acc['username'],
                    email=acc['email'],
                    role=acc['role'],
                    is_active=True,
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None)
                )
                user.set_password(acc['password'])
                db.session.add(user)
                db.session.flush()

                # Audit log user creation
                log_event(
                    actor=user,
                    action="user.seed",
                    target_type="user",
                    target_id=user.id,
                    outcome="allowed",
                    detail=f"Seeded demo account '{user.username}' with role '{user.role}'",
                    org_id=org.id
                )
            created_users[acc['role']] = user

        # Create sample document owned by demo_owner
        owner_user = created_users.get('owner') or User.query.filter_by(username='demo_owner').first()
        viewer_user = created_users.get('viewer') or User.query.filter_by(username='demo_viewer').first()

        if owner_user:
            doc = Document.query.filter_by(title="Welcome to TrustVault Guide", org_id=org.id).first()
            if doc is None:
                doc_bytes = (
                    b"%PDF-1.4\n% TrustVault Multi-Tenant Document Sharing System\n"
                    b"Welcome to TrustVault! This sample document is stored as a BLOB in PostgreSQL/SQLite.\n"
                    b"Strict multi-tenancy ensures data never crosses organization boundaries.\n%%EOF"
                )
                doc = Document(
                    org_id=org.id,
                    owner_id=owner_user.id,
                    title="Welcome to TrustVault Guide",
                    description="Official platform welcome guide and multi-tenant security overview.",
                    filename="welcome_guide.pdf",
                    mime_type="application/pdf",
                    size=len(doc_bytes),
                    sha256=hashlib.sha256(doc_bytes).hexdigest(),
                    data=doc_bytes,
                    version=1,
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None)
                )
                db.session.add(doc)
                db.session.flush()

                log_event(
                    actor=owner_user,
                    action="document.seed",
                    target_type="document",
                    target_id=doc.id,
                    outcome="allowed",
                    detail=f"Seeded sample document '{doc.title}'",
                    org_id=org.id
                )

            # Grant read access to demo_viewer if not already active
            if doc and viewer_user:
                grant = AccessGrant.query.filter_by(
                    document_id=doc.id,
                    user_id=viewer_user.id,
                    revoked_at=None
                ).first()
                if grant is None:
                    grant = AccessGrant(
                        document_id=doc.id,
                        user_id=viewer_user.id,
                        permission='read',
                        granted_by=owner_user.id,
                        created_at=datetime.now(timezone.utc).replace(tzinfo=None)
                    )
                    db.session.add(grant)
                    db.session.flush()

                    log_event(
                        actor=owner_user,
                        action="access.grant",
                        target_type="access_grant",
                        target_id=grant.id,
                        outcome="allowed",
                        detail=f"Seeded read grant on '{doc.title}' for user '{viewer_user.username}'",
                        org_id=org.id
                    )

        db.session.commit()

        if print_banner:
            # Display formatted credentials box
            banner = "=" * 72
            divider = "-" * 72
            click.echo("")
            click.echo(banner)
            click.echo("           TrustVault: Demo Environment Seeded Successfully!           ")
            click.echo(banner)
            click.echo(f" Organization: {demo_org_name}")
            click.echo(divider)
            for acc in demo_accounts:
                click.echo(f" Role:     {acc['role'].upper()}")
                click.echo(f" Username: {acc['username']}")
                click.echo(f" Password: {acc['password']}")
                click.echo(f" Email:    {acc['email']}")
                click.echo(f" Access:   {acc['description']}")
                click.echo(divider)
            click.echo(" Sample document 'Welcome to TrustVault Guide' is uploaded and shared")
            click.echo(" with 'demo_viewer' (read-only).")
            click.echo(banner)
            click.echo("")

    @app.cli.command('seed-db')
    def seed_db():
        """Seed the database with a demo organization, users, and sample document."""
        _execute_seed(print_banner=True)

    @app.cli.command('seed')
    def seed():
        """Alias for seed-db: Seed demo organization and users."""
        _execute_seed(print_banner=True)

    # Auto-seed when SEED_DEMO=1 (e.g. on Render free tier without web shell)
    if os.environ.get('SEED_DEMO') == '1':
        with app.app_context():
            try:
                _execute_seed(print_banner=False)
            except Exception as e:
                app.logger.warning(f"Auto-seeding failed or skipped: {e}")

    # Root route: redirects to dashboard if authenticated, or login if guest
    @app.route('/')
    def index():
        from flask_login import current_user
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

    # Defensive HTTP security headers applied to all responses
    @app.after_request
    def set_security_headers(response):
        """Apply defensive security headers to mitigate XSS, clickjacking, and MIME sniffing."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        return response


    # Custom error handlers providing clean error pages without stack traces
    @app.errorhandler(403)
    def forbidden_error(error):
        """Render custom 403 Forbidden page without internal details."""
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        """Render custom 404 Not Found page without internal details."""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Render custom 500 Internal Server Error page and rollback aborted database transactions."""
        db.session.rollback()
        return render_template('errors/500.html'), 500

    return app

