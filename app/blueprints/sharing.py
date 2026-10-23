"""
Sharing and Access Management Blueprint for TrustVault.

Manages delegating document access (granting, changing permissions, and revoking)
within the SAME organization.

Security & Tenancy Rules:
1. Every route enforces require('manage_access', document).
2. Viewers and non-owners attempting to access these endpoints are strictly rejected
   with HTTP 403 Forbidden, and the denied attempt is recorded in the audit log.
3. Access can ONLY be granted to active users belonging to the SAME organization.
4. Revocation sets `revoked_at` timestamp and takes effect immediately on subsequent requests.
5. Every grant, permission change, and revocation is recorded in the hash-chained audit log
   with the target user in detail.
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from extensions import db
from app.models import Document, User, AccessGrant
from app.permissions import can, require
from app.audit import log_event
from app.forms import GrantAccessForm, ChangePermissionForm

sharing_bp = Blueprint('sharing', __name__, url_prefix='/documents/<int:doc_id>/sharing')


def _get_document_for_manage_access(doc_id: int):
    """
    Look up document strictly scoped to the user's organization and enforce require('manage_access').

    Security Guarantees:
    - Scoped by document id AND current_user.org_id.
    - Soft-deleted documents return 404.
    - If user lacks 'manage_access' (e.g. viewers or non-owners), logs denied audit event
      and calls require('manage_access', doc) to abort with 403 Forbidden.
    """
    doc = Document.query.filter_by(
        id=doc_id,
        org_id=current_user.org_id,
        deleted_at=None
    ).first()

    if doc is None:
        # Check if the document exists in another organization for audit trail
        other_tenant_doc = db.session.get(Document, doc_id)
        if other_tenant_doc is not None and other_tenant_doc.org_id != current_user.org_id:
            log_event(
                actor=current_user,
                action="document.manage_access",
                target_type="document",
                target_id=doc_id,
                outcome="denied",
                detail="Cross-tenant access management attempt blocked"
            )
        abort(404)

    # Server-side authorization check: viewers and non-owners get 403
    if not can(current_user, 'manage_access', doc):
        log_event(
            actor=current_user,
            action="document.manage_access",
            target_type="document",
            target_id=doc.id,
            outcome="denied",
            detail=f"Unauthorized access management attempt by {current_user.role} on document '{doc.title}'"
        )
        require('manage_access', doc)  # Aborts with 403 Forbidden

    return doc


@sharing_bp.route('/', methods=['GET'])
@login_required
def manage_access(doc_id: int):
    """
    Display the 'Manage access' dashboard for a document:
    - Lists active access grants.
    - Provides a form to grant access to other colleagues in the same organization.
    """
    doc = _get_document_for_manage_access(doc_id)

    # Retrieve all active grants on this document
    active_grants = (
        AccessGrant.query
        .filter_by(document_id=doc.id, revoked_at=None)
        .order_by(AccessGrant.created_at.desc())
        .all()
    )

    # Find users in the SAME organization eligible to receive access
    # (Exclude document owner and users who already have active grants)
    active_granted_user_ids = {g.user_id for g in active_grants}
    active_granted_user_ids.add(doc.owner_id)

    eligible_users = (
        User.query
        .filter(
            User.org_id == current_user.org_id,
            User.is_active.is_(True),
            User.id.notin_(active_granted_user_ids)
        )
        .order_by(User.username.asc())
        .all()
    )

    grant_form = GrantAccessForm()
    grant_form.user_id.choices = [(u.id, f"{u.username} ({u.role.capitalize()}) - {u.email}") for u in eligible_users]

    change_form = ChangePermissionForm()

    return render_template(
        'sharing/manage.html',
        doc=doc,
        active_grants=active_grants,
        grant_form=grant_form,
        change_form=change_form,
        eligible_users_count=len(eligible_users)
    )


@sharing_bp.route('/grant', methods=['POST'])
@login_required
def grant_access(doc_id: int):
    """
    Grant read or edit access on a document to another user in the SAME organization.
    """
    doc = _get_document_for_manage_access(doc_id)

    # Populate choices for validation
    eligible_users = (
        User.query
        .filter(User.org_id == current_user.org_id, User.is_active.is_(True))
        .all()
    )
    grant_form = GrantAccessForm()
    grant_form.user_id.choices = [(u.id, u.username) for u in eligible_users]

    if grant_form.validate_on_submit():
        target_user_id = grant_form.user_id.data
        permission = grant_form.permission.data

        if permission not in {'read', 'edit'}:
            flash("Invalid permission level requested.", "danger")
            return redirect(url_for('sharing.manage_access', doc_id=doc.id))

        # Strict Multi-Tenancy Validation: Target user MUST belong to the SAME organization
        target_user = User.query.filter_by(
            id=target_user_id,
            org_id=current_user.org_id
        ).first()

        if target_user is None or not target_user.is_active:
            log_event(
                actor=current_user,
                action="access.grant",
                target_type="document",
                target_id=doc.id,
                outcome="denied",
                detail=f"Grant access blocked: target user id={target_user_id} does not belong to user's organization or is inactive"
            )
            flash("Target user not found in your organization.", "danger")
            return redirect(url_for('sharing.manage_access', doc_id=doc.id))

        if target_user.id == doc.owner_id:
            flash("Document owner already has complete access to this document.", "warning")
            return redirect(url_for('sharing.manage_access', doc_id=doc.id))

        # Check for existing active grant
        existing_active_grant = AccessGrant.query.filter_by(
            document_id=doc.id,
            user_id=target_user.id,
            revoked_at=None
        ).first()

        if existing_active_grant is not None:
            flash(
                f"User '{target_user.username}' already has active access. "
                "You can change their permission level below.",
                "info"
            )
            return redirect(url_for('sharing.manage_access', doc_id=doc.id))

        # Create new access grant
        grant = AccessGrant(
            document_id=doc.id,
            user_id=target_user.id,
            permission=permission,
            granted_by=current_user.id,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(grant)
        db.session.commit()

        # Audit log the grant with target user details
        log_event(
            actor=current_user,
            action="access.grant",
            target_type="access_grant",
            target_id=grant.id,
            outcome="allowed",
            detail=f"Granted '{permission}' access on document '{doc.title}' to user '{target_user.username}' (id={target_user.id})"
        )

        flash(f"Granted {permission.capitalize()} access to '{target_user.username}'.", "success")
        return redirect(url_for('sharing.manage_access', doc_id=doc.id))

    flash("Please select a valid user and permission level.", "danger")
    return redirect(url_for('sharing.manage_access', doc_id=doc.id))


@sharing_bp.route('/<int:grant_id>/change', methods=['POST'])
@login_required
def change_permission(doc_id: int, grant_id: int):
    """
    Change the permission level of an active grant (e.g. read -> edit or edit -> read).
    """
    doc = _get_document_for_manage_access(doc_id)

    grant = AccessGrant.query.filter_by(
        id=grant_id,
        document_id=doc.id,
        revoked_at=None
    ).first()

    if grant is None:
        abort(404)

    new_permission = request.form.get('permission')
    if new_permission not in {'read', 'edit'}:
        flash("Invalid permission level requested.", "danger")
        return redirect(url_for('sharing.manage_access', doc_id=doc.id))

    old_permission = grant.permission
    if old_permission != new_permission:
        grant.permission = new_permission
        db.session.commit()

        target_user = db.session.get(User, grant.user_id)
        target_name = target_user.username if target_user else f"user_{grant.user_id}"

        # Audit log the permission change with target user in detail
        log_event(
            actor=current_user,
            action="access.change",
            target_type="access_grant",
            target_id=grant.id,
            outcome="allowed",
            detail=(
                f"Changed permission from '{old_permission}' to '{new_permission}' "
                f"for user '{target_name}' (id={grant.user_id}) on document '{doc.title}'"
            )
        )

        flash(f"Updated permission for '{target_name}' to {new_permission.capitalize()}.", "success")

    return redirect(url_for('sharing.manage_access', doc_id=doc.id))


@sharing_bp.route('/<int:grant_id>/revoke', methods=['POST'])
@login_required
def revoke_access(doc_id: int, grant_id: int):
    """
    Revoke an active grant.
    Sets revoked_at and takes effect immediately on the next request.
    """
    doc = _get_document_for_manage_access(doc_id)

    grant = AccessGrant.query.filter_by(
        id=grant_id,
        document_id=doc.id,
        revoked_at=None
    ).first()

    if grant is None:
        abort(404)

    # Immediately revoke the grant
    grant.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()

    target_user = db.session.get(User, grant.user_id)
    target_name = target_user.username if target_user else f"user_{grant.user_id}"

    # Audit log the revocation with target user in detail
    log_event(
        actor=current_user,
        action="access.revoke",
        target_type="access_grant",
        target_id=grant.id,
        outcome="allowed",
        detail=(
            f"Revoked '{grant.permission}' access for user '{target_name}' "
            f"(id={grant.user_id}) on document '{doc.title}'"
        )
    )

    flash(f"Revoked access for '{target_name}'.", "info")
    return redirect(url_for('sharing.manage_access', doc_id=doc.id))
