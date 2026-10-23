"""
Authentication Blueprint for TrustVault.

Handles user registration, login, and logout.
Key security and tenancy rules:
1. Registration creates a brand-new Organization and registers the user as its 'admin'.
2. Generic error messages prevent username enumeration on bad login attempts.
3. Passwords must be at least 10 characters long, hashed securely with Werkzeug.
4. Rate limiting locks an account for 10 minutes after 5 consecutive failed login attempts.
5. All forms enforce CSRF protection via Flask-WTF.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db
from app.models import Organization, User
from app.forms import LoginForm, RegisterForm
from app.audit import log_event

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Pre-computed dummy password hash used to equalize execution timing on non-existent usernames
_DUMMY_PASSWORD_HASH = generate_password_hash("ConstantTimingDummySecretKey123!")

# -----------------------------------------------------------------------------
# Rate-Limiting & Lockout Tracker
# -----------------------------------------------------------------------------
# Tracks timestamps of failed login attempts per normalized username.
# Key: normalized username (lowercase) -> Value: list of UTC datetime timestamps.
_failed_login_attempts = defaultdict(list)
_lockout_lock = threading.Lock()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 10
LOCKOUT_DURATION = timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
MAX_LOCKOUT_ENTRIES = 10000


def _sanitize_log_input(val: str, max_len: int = 64) -> str:
    """
    Sanitize and truncate string input for safe logging.
    - Strips whitespace.
    - Escapes carriage returns, newlines, and tabs to prevent CRLF log injection.
    - Truncates to max_len characters to prevent log buffer exhaustion.
    """
    if not val:
        return ""
    sanitized = val.strip().replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + "..."
    return sanitized


def _cleanup_expired_lockouts_locked(now):
    """
    Purge expired lockout entries from _failed_login_attempts.
    Must be called with _lockout_lock held.
    """
    cutoff = now - LOCKOUT_DURATION
    expired_keys = []
    for k, timestamps in list(_failed_login_attempts.items()):
        recent = [t for t in timestamps if t > cutoff]
        if not recent:
            expired_keys.append(k)
        else:
            _failed_login_attempts[k] = recent
    for k in expired_keys:
        _failed_login_attempts.pop(k, None)


def is_account_locked(username: str) -> bool:
    """
    Check if a given username has exceeded the maximum allowed failed login attempts.

    Returns:
        bool: True if locked out for the 10-minute window, False otherwise.
    """
    if not username:
        return False
    key = username.strip().lower()
    now = datetime.now(timezone.utc)
    cutoff = now - LOCKOUT_DURATION

    with _lockout_lock:
        if key not in _failed_login_attempts:
            return False
        # Filter attempts within the 10-minute lockout window
        recent = [t for t in _failed_login_attempts[key] if t > cutoff]
        if not recent:
            _failed_login_attempts.pop(key, None)
            return False
        _failed_login_attempts[key] = recent
        return len(recent) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(username: str):
    """
    Record a failed login attempt timestamp for a username.
    Enforces maximum entry capacity (MAX_LOCKOUT_ENTRIES) and purges expired entries.
    """
    if not username:
        return
    key = username.strip().lower()
    now = datetime.now(timezone.utc)
    cutoff = now - LOCKOUT_DURATION

    with _lockout_lock:
        # Periodic expiration cleanup when capacity threshold is reached
        if len(_failed_login_attempts) >= MAX_LOCKOUT_ENTRIES:
            _cleanup_expired_lockouts_locked(now)
            # If still at or over capacity, evict the oldest key (FIFO)
            while len(_failed_login_attempts) >= MAX_LOCKOUT_ENTRIES:
                oldest_key = next(iter(_failed_login_attempts))
                _failed_login_attempts.pop(oldest_key, None)

        recent = [t for t in _failed_login_attempts.get(key, []) if t > cutoff]
        recent.append(now)
        _failed_login_attempts[key] = recent


def clear_failed_attempts(username: str):
    """
    Reset failed login attempts upon successful authentication.
    """
    if not username:
        return
    key = username.strip().lower()
    with _lockout_lock:
        _failed_login_attempts.pop(key, None)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Register a new Organization (tenant) and its initial Admin user.

    Every organization starts with an Admin user who has full control over
    documents and user accounts within that organization.
    """
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        org_name = form.organization_name.data.strip()
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        # Double check password length requirement (at least 10 characters)
        if len(password) < 10:
            flash("Password must be at least 10 characters long.", "danger")
            return render_template('auth/register.html', form=form)

        # 1. Create the new Organization
        org = Organization(name=org_name)
        db.session.add(org)
        db.session.flush()  # Generates org.id for the user association

        # 2. Create the Admin user for this new organization
        user = User(
            org_id=org.id,
            username=username,
            email=email,
            role='admin',
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Automatically log the new admin in
        login_user(user)

        # Record registration in the organization's audit trail (genesis block)
        log_event(
            actor=user,
            action="auth.register",
            target_type="organization",
            target_id=org.id,
            outcome="allowed",
            detail=f"Registered organization '{org.name}' with initial administrator '{user.username}'"
        )

        flash(f"Organization '{org.name}' created successfully! You are signed in as Admin.", "success")
        return redirect(url_for('auth.dashboard'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Authenticate an existing user.

    Security safeguards:
    - Lockout after 5 failed attempts for 10 minutes.
    - Generic error message ('Invalid username or password') to avoid revealing
      whether a username exists.
    """
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        # 1. Check if the username is currently locked out
        if is_account_locked(username):
            sanitized_user = _sanitize_log_input(username)
            user = User.query.filter_by(username=username).first()
            if user:
                log_event(
                    actor=user,
                    action="auth.login",
                    target_type="user",
                    target_id=user.id,
                    outcome="denied",
                    detail=f"Login blocked: account locked for username '{sanitized_user}'"
                )
            else:
                current_app.logger.warning(
                    f"Security: Login blocked due to lockout for non-existent username '{sanitized_user}' from IP {request.remote_addr}"
                )
            flash(
                "Account temporarily locked due to too many failed login attempts. "
                "Please try again in 10 minutes.",
                "danger"
            )
            return render_template('auth/login.html', form=form), 429

        # 2. Lookup the user
        user = User.query.filter_by(username=username).first()

        # 3. Verify credentials (constant-time check equalizing execution timing)
        if user is not None:
            password_valid = user.check_password(password)
        else:
            # Run dummy password-hash check to equalize execution timing across valid/invalid users
            check_password_hash(_DUMMY_PASSWORD_HASH, password)
            password_valid = False

        if not password_valid:
            # Record failed attempt regardless of whether user exists (rate-limiting defense)
            record_failed_attempt(username)
            sanitized_user = _sanitize_log_input(username)
            # Log denied event if user is an existing account
            if user is not None:
                log_event(
                    actor=user,
                    action="auth.login",
                    target_type="user",
                    target_id=user.id,
                    outcome="denied",
                    detail=f"Failed login attempt: invalid credentials for '{sanitized_user}'"
                )
            else:
                # Log failed attempt for unknown username to application security log
                # (Cannot be stored in tenant audit log because AuditLog requires an org_id)
                current_app.logger.warning(
                    f"Security: Failed login attempt for non-existent username '{sanitized_user}' from IP {request.remote_addr}"
                )
            # Generic error message: do NOT disclose if username exists
            flash("Invalid username or password.", "danger")
            return render_template('auth/login.html', form=form)

        # 4. Check if account is active
        if not user.is_active:
            log_event(
                actor=user,
                action="auth.login",
                target_type="user",
                target_id=user.id,
                outcome="denied",
                detail=f"Failed login attempt: account is inactive for '{username}'"
            )
            flash("This account is currently inactive. Contact your organization administrator.", "danger")
            return render_template('auth/login.html', form=form)

        # 5. Successful login: clear lockout history, log in user, and audit log
        clear_failed_attempts(username)
        login_user(user, remember=form.remember_me.data)
        log_event(
            actor=user,
            action="auth.login",
            target_type="user",
            target_id=user.id,
            outcome="allowed",
            detail=f"User '{user.username}' successfully logged in"
        )
        flash("Signed in successfully.", "success")

        # 6. Redirect to requested page (with protection against open redirect attacks)
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('auth.dashboard')

        return redirect(next_page)

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """
    Log out the currently authenticated user.
    """
    user = current_user._get_current_object()
    log_event(
        actor=user,
        action="auth.logout",
        target_type="user",
        target_id=user.id,
        outcome="allowed",
        detail=f"User '{user.username}' logged out"
    )
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """
    Landing dashboard for authenticated users showing their tenant context and role.
    """
    return render_template('auth/dashboard.html')
