"""
Admin Blueprint for TrustVault.

Provides administrative controls strictly isolated to the administrator's
own organization (tenant):
1. User Management for own org:
   - Create new user accounts with designated roles (admin, owner, viewer).
   - Deactivate and reactivate existing user accounts.
   - Change user roles.
   - SAFETY RULE: An administrator cannot demote or deactivate the last active admin.
2. Tamper-Evident Audit Log Page:
   - Filterable view of all tenant audit records (by action, actor, target type, outcome, query).
   - "Verify chain" action that cryptographically validates SHA-256 hash chains
     and pinpoints any broken entries.
3. Organization-Wide Document Repository:
   - Comprehensive roster of all documents belonging to the organization.
   - Direct access to inspect, download, manage permissions, or delete documents.

Authorization & Auditing Rules:
- All routes require authentication and enforce `require('manage_users')` or `require('view_audit')`.
- Non-admin attempts return 403 Forbidden and record a DENIED entry in the audit log.
- All administrative actions (allowed and denied) are logged via `log_event()`.
"""

from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, abort
)
from flask_login import login_required, current_user
from extensions import db
from app.models import User, Document, AuditLog
from app.permissions import can, require
from app.audit import log_event, verify_chain
from app.forms import CreateUserForm, ChangeRoleForm

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def _enforce_admin_permission(action: str):
    """
    Enforces authorization for administrative actions.

    If current_user lacks the required permission:
    1. Appends a DENIED attempt to the organization's tamper-evident audit log.
    2. Aborts with HTTP 403 Forbidden.
    """
    if not can(current_user, action):
        log_event(
            actor=current_user,
            action=f"admin.{action}",
            target_type="admin",
            outcome="denied",
            detail=f"Unauthorized '{action}' attempt by role '{getattr(current_user, 'role', 'unknown')}'"
        )
        require(action)  # Aborts with 403 Forbidden


@admin_bp.route('/', methods=['GET'])
@login_required
def index():
    """Redirect admin root to the user management console."""
    _enforce_admin_permission('manage_users')
    return redirect(url_for('admin.users_list'))


# -----------------------------------------------------------------------------
# 1. User Management Routes
# -----------------------------------------------------------------------------

@admin_bp.route('/users', methods=['GET'])
@login_required
def users_list():
    """
    Display the roster of all users within the current user's organization.
    Includes forms to register new users and change existing user roles.
    """
    _enforce_admin_permission('manage_users')

    # Fetch all users strictly belonging to the admin's organization
    users = (
        User.query
        .filter_by(org_id=current_user.org_id)
        .order_by(User.created_at.asc())
        .all()
    )

    create_form = CreateUserForm()
    change_role_form = ChangeRoleForm()

    # Log viewing the user management console
    log_event(
        actor=current_user,
        action="user.list",
        target_type="organization",
        target_id=current_user.org_id,
        outcome="allowed",
        detail=f"Admin '{current_user.username}' viewed user roster ({len(users)} users)"
    )

    return render_template(
        'admin/users.html',
        users=users,
        create_form=create_form,
        change_role_form=change_role_form
    )


@admin_bp.route('/users/create', methods=['POST'])
@login_required
def create_user():
    """
    Create a new user within the current user's organization.
    """
    _enforce_admin_permission('manage_users')

    create_form = CreateUserForm()

    if create_form.validate_on_submit():
        username = create_form.username.data.strip()
        email = create_form.email.data.strip().lower()
        password = create_form.password.data
        role = create_form.role.data

        # Multi-Tenancy Guarantee: user is explicitly bound to current_user.org_id
        new_user = User(
            org_id=current_user.org_id,
            username=username,
            email=email,
            role=role,
            is_active=True,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        # Audit log the user creation
        log_event(
            actor=current_user,
            action="user.create",
            target_type="user",
            target_id=new_user.id,
            outcome="allowed",
            detail=f"Admin '{current_user.username}' created user '{username}' with role '{role}' ({email})"
        )

        flash(f"User '{username}' created successfully as {role.capitalize()}.", "success")
        return redirect(url_for('admin.users_list'))

    # If form validation fails, flash the specific errors
    for field, errors in create_form.errors.items():
        for error in errors:
            flash(f"Error in {field}: {error}", "danger")

    return redirect(url_for('admin.users_list'))


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id: int):
    """
    Deactivate or reactivate a user account in the organization.

    SAFETY RULE:
    An administrator CANNOT deactivate the last active administrator in the organization.
    """
    _enforce_admin_permission('manage_users')

    # Multi-tenant lookup: Target user MUST belong to current_user.org_id
    target_user = User.query.filter_by(
        id=user_id,
        org_id=current_user.org_id
    ).first()

    if target_user is None:
        log_event(
            actor=current_user,
            action="user.toggle_status",
            target_type="user",
            target_id=user_id,
            outcome="denied",
            detail=f"User status toggle failed: user id={user_id} not found in organization"
        )
        abort(404)

    # Check if deactivation is being requested
    if target_user.is_active:
        # Check safety rule: cannot deactivate the last active admin
        if target_user.role == 'admin':
            active_admin_count = User.query.filter_by(
                org_id=current_user.org_id,
                role='admin',
                is_active=True
            ).count()

            if active_admin_count <= 1:
                log_event(
                    actor=current_user,
                    action="user.deactivate",
                    target_type="user",
                    target_id=target_user.id,
                    outcome="denied",
                    detail=f"Blocked attempt to deactivate the last active admin '{target_user.username}'"
                )
                flash("Cannot deactivate the only active administrator in the organization.", "danger")
                return redirect(url_for('admin.users_list'))

        # Deactivate user
        target_user.is_active = False
        db.session.commit()

        log_event(
            actor=current_user,
            action="user.deactivate",
            target_type="user",
            target_id=target_user.id,
            outcome="allowed",
            detail=f"Deactivated user '{target_user.username}' (id={target_user.id})"
        )
        flash(f"User '{target_user.username}' has been deactivated.", "info")

    else:
        # Reactivate user
        target_user.is_active = True
        db.session.commit()

        log_event(
            actor=current_user,
            action="user.reactivate",
            target_type="user",
            target_id=target_user.id,
            outcome="allowed",
            detail=f"Reactivated user '{target_user.username}' (id={target_user.id})"
        )
        flash(f"User '{target_user.username}' has been reactivated.", "success")

    return redirect(url_for('admin.users_list'))


@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@login_required
def change_user_role(user_id: int):
    """
    Change a user's role (admin, owner, or viewer).

    SAFETY RULE:
    An administrator CANNOT demote the last active administrator in the organization.
    """
    _enforce_admin_permission('manage_users')

    # Multi-tenant lookup: Target user MUST belong to current_user.org_id
    target_user = User.query.filter_by(
        id=user_id,
        org_id=current_user.org_id
    ).first()

    if target_user is None:
        log_event(
            actor=current_user,
            action="user.change_role",
            target_type="user",
            target_id=user_id,
            outcome="denied",
            detail=f"Role change failed: user id={user_id} not found in organization"
        )
        abort(404)

    new_role = request.form.get('role', '').strip().lower()
    if new_role not in {'admin', 'owner', 'viewer'}:
        flash("Invalid role specified.", "danger")
        return redirect(url_for('admin.users_list'))

    # If the user is currently an active admin and changing to a non-admin role:
    if target_user.role == 'admin' and new_role != 'admin' and target_user.is_active:
        active_admin_count = User.query.filter_by(
            org_id=current_user.org_id,
            role='admin',
            is_active=True
        ).count()

        if active_admin_count <= 1:
            log_event(
                actor=current_user,
                action="user.change_role",
                target_type="user",
                target_id=target_user.id,
                outcome="denied",
                detail=f"Blocked attempt to demote the last active admin '{target_user.username}' to '{new_role}'"
            )
            flash("Cannot demote the only active administrator in the organization.", "danger")
            return redirect(url_for('admin.users_list'))

    old_role = target_user.role
    if old_role != new_role:
        target_user.role = new_role
        db.session.commit()

        log_event(
            actor=current_user,
            action="user.change_role",
            target_type="user",
            target_id=target_user.id,
            outcome="allowed",
            detail=f"Changed role for user '{target_user.username}' (id={target_user.id}) from '{old_role}' to '{new_role}'"
        )
        flash(f"Updated role for '{target_user.username}' to {new_role.capitalize()}.", "success")

    return redirect(url_for('admin.users_list'))


# -----------------------------------------------------------------------------
# 2. Audit Log & Hash Chain Verification Routes
# -----------------------------------------------------------------------------

@admin_bp.route('/audit', methods=['GET'])
@login_required
def audit_log():
    """
    Display the tamper-evident audit trail with filtering and chain verification controls.
    """
    _enforce_admin_permission('view_audit')

    # Extract query filters
    action_filter = request.args.get('action', '').strip()
    actor_id_filter = request.args.get('actor_id', '').strip()
    target_type_filter = request.args.get('target_type', '').strip()
    outcome_filter = request.args.get('outcome', '').strip()
    search_q = request.args.get('q', '').strip()

    # Log viewing of the audit trail
    log_event(
        actor=current_user,
        action="audit.view",
        target_type="organization",
        target_id=current_user.org_id,
        outcome="allowed",
        detail="Admin viewed organization audit trail"
    )

    # Base query: strictly isolated to the admin's tenant
    query = AuditLog.query.filter_by(org_id=current_user.org_id)

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    if actor_id_filter and actor_id_filter.isdigit():
        query = query.filter(AuditLog.actor_id == int(actor_id_filter))

    if target_type_filter:
        query = query.filter(AuditLog.target_type == target_type_filter)

    if outcome_filter in {'allowed', 'denied'}:
        query = query.filter(AuditLog.outcome == outcome_filter)

    if search_q:
        query = query.filter(
            db.or_(
                AuditLog.detail.ilike(f"%{search_q}%"),
                AuditLog.action.ilike(f"%{search_q}%"),
                AuditLog.ip_address.ilike(f"%{search_q}%")
            )
        )

    # Fetch audit events newest first
    entries = query.order_by(AuditLog.id.desc()).all()

    # Retrieve distinct actions and users for dropdown filter options
    distinct_actions = [
        r[0] for r in db.session.query(AuditLog.action)
        .filter_by(org_id=current_user.org_id)
        .distinct()
        .order_by(AuditLog.action.asc())
        .all()
    ]
    org_users = (
        User.query
        .filter_by(org_id=current_user.org_id)
        .order_by(User.username.asc())
        .all()
    )

    # Check if a verification result was passed in query params
    verification_status = None
    if request.args.get('verified') == '1':
        verification_status = {
            'ok': request.args.get('valid') == '1',
            'broken_id': request.args.get('broken_id')
        }

    return render_template(
        'admin/audit.html',
        entries=entries,
        distinct_actions=distinct_actions,
        org_users=org_users,
        current_filters={
            'action': action_filter,
            'actor_id': actor_id_filter,
            'target_type': target_type_filter,
            'outcome': outcome_filter,
            'q': search_q
        },
        verification_status=verification_status
    )


@admin_bp.route('/audit/verify', methods=['POST'])
@login_required
def verify_audit_chain():
    """
    Cryptographically verify the entire audit log chain for the organization.
    Detects any modifications, deletions, or out-of-order insertions.
    """
    _enforce_admin_permission('view_audit')

    is_valid, first_broken_id = verify_chain(current_user.org_id)

    # Audit log the verification operation itself
    log_event(
        actor=current_user,
        action="audit.verify",
        target_type="organization",
        target_id=current_user.org_id,
        outcome="allowed",
        detail=f"Cryptographic chain verification completed. Valid={is_valid}, BrokenId={first_broken_id}"
    )

    if is_valid:
        flash("Audit log chain verified: all records are intact and tamper-evident hashes are valid.", "success")
    else:
        flash(f"Audit log integrity compromised: cryptographic chain broken at entry #{first_broken_id}.", "danger")

    return redirect(url_for(
        'admin.audit_log',
        verified='1',
        valid='1' if is_valid else '0',
        broken_id=first_broken_id or ''
    ))


# -----------------------------------------------------------------------------
# 3. Organization-Wide Document Repository Routes
# -----------------------------------------------------------------------------

@admin_bp.route('/documents', methods=['GET'])
@login_required
def documents_list():
    """
    Display all documents across the entire organization.
    Protected with require('manage_users') to ensure administrator access only.
    """
    _enforce_admin_permission('manage_users')

    search_q = request.args.get('q', '').strip()
    show_deleted = request.args.get('show_deleted') == '1'

    # Base query: strictly scoped to the admin's organization
    query = Document.query.filter_by(org_id=current_user.org_id)

    if not show_deleted:
        query = query.filter_by(deleted_at=None)

    if search_q:
        query = query.filter(
            db.or_(
                Document.title.ilike(f"%{search_q}%"),
                Document.filename.ilike(f"%{search_q}%"),
                Document.description.ilike(f"%{search_q}%")
            )
        )

    documents = query.order_by(Document.created_at.desc()).all()

    # Calculate summary metrics
    total_active = Document.query.filter_by(org_id=current_user.org_id, deleted_at=None).count()
    total_deleted = Document.query.filter(
        Document.org_id == current_user.org_id,
        Document.deleted_at.isnot(None)
    ).count()

    total_storage_bytes = db.session.query(db.func.sum(Document.size)).filter(
        Document.org_id == current_user.org_id,
        Document.deleted_at == None  # noqa: E711
    ).scalar() or 0

    # Log viewing of org-wide documents
    log_event(
        actor=current_user,
        action="admin.documents.view",
        target_type="organization",
        target_id=current_user.org_id,
        outcome="allowed",
        detail=f"Admin viewed org documents repository ({len(documents)} displayed)"
    )

    return render_template(
        'admin/documents.html',
        documents=documents,
        total_active=total_active,
        total_deleted=total_deleted,
        total_storage_bytes=total_storage_bytes,
        search_q=search_q,
        show_deleted=show_deleted
    )
