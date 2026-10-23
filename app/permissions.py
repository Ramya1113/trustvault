"""
Centralized Server-Side Authorization for TrustVault.

CRITICAL ARCHITECTURE REQUIREMENT:
ALL authorization logic in TrustVault must be defined here.
Never rely on UI obfuscation or hiding buttons. Every endpoint, view,
and API operation MUST verify permissions through `can()` or `require()`.

Supported Actions:
- 'view': View document metadata and preview content.
- 'download': Download the binary file payload of a document.
- 'edit': Update or replace document metadata and content.
- 'delete': Soft-delete a document.
- 'manage_access': Grant or revoke permissions on a document to other users.
- 'manage_users': Create, update, or deactivate user accounts in the organization.
- 'view_audit': Read the organization's hash-chained audit log.
"""

from functools import wraps
from flask import abort, has_request_context
from flask_login import current_user

# All valid actions recognized by the system
DOCUMENT_ACTIONS = {'view', 'download', 'edit', 'delete', 'manage_access'}
ORG_ACTIONS = {'manage_users', 'view_audit', 'upload'}
VALID_ACTIONS = DOCUMENT_ACTIONS | ORG_ACTIONS


def _get_active_grant(user, document):
    """
    Helper to find an active (non-revoked) AccessGrant for a given user on a document.
    Queries the database first by document_id and user_id, falling back to in-memory
    collection inspection for mock objects.
    """
    # Query database directly if both entities have persisted IDs
    if getattr(document, 'id', None) is not None and getattr(user, 'id', None) is not None:
        from app.models import AccessGrant
        return AccessGrant.query.filter_by(
            document_id=document.id,
            user_id=user.id,
            revoked_at=None
        ).first()

    # Fallback for uncommitted/mock objects
    if getattr(document, 'access_grants', None) is not None:
        try:
            for g in document.access_grants:
                if getattr(g, 'user_id', None) == getattr(user, 'id', None) and getattr(g, 'revoked_at', None) is None:
                    return g
        except Exception:
            pass

    return None


def can(user, action: str, document=None) -> bool:
    """
    Evaluate whether a user is authorized to perform an action on an optional document.

    Args:
        user: The User instance requesting permission.
        action (str): The requested action (view, download, edit, delete,
                      manage_access, manage_users, view_audit).
        document: The Document instance being accessed (None for org-level actions).

    Returns:
        bool: True if authorized, False otherwise.
    """
    # -------------------------------------------------------------------------
    # RULE 1: User Validity Check
    # Rationale: Anonymous users, non-existent users, or disabled/deactivated
    # accounts must never be allowed to perform any action in the system.
    # -------------------------------------------------------------------------
    if user is None or not getattr(user, 'is_active', False):
        return False

    # -------------------------------------------------------------------------
    # RULE 2: Action Validity Check
    # Rationale: Fail closed if an unsupported or unrecognized action is requested.
    # -------------------------------------------------------------------------
    if action not in VALID_ACTIONS:
        return False

    # -------------------------------------------------------------------------
    # RULE 3: Target Document Requirement for Document Actions
    # Rationale: Document-specific actions (view, download, edit, delete, manage_access)
    # cannot be performed without a concrete target document.
    # -------------------------------------------------------------------------
    if action in DOCUMENT_ACTIONS and document is None:
        return False

    if document is not None:
        # ---------------------------------------------------------------------
        # RULE 4: Strict Multi-Tenant Isolation (ALWAYS CHECKED FIRST)
        # Rationale: TrustVault is strictly multi-tenant. No user may EVER access,
        # view, or manage a document belonging to another organization. This check
        # precedes all role and ownership evaluations without exception.
        # ---------------------------------------------------------------------
        if document.org_id != user.org_id:
            return False

        # ---------------------------------------------------------------------
        # RULE 5: Soft-Deleted Document Check
        # Rationale: Soft-deleted documents are archived and tombstoned.
        # No regular operations (view, download, edit, delete, manage_access)
        # are permitted on deleted documents.
        # ---------------------------------------------------------------------
        if getattr(document, 'is_deleted', False) or getattr(document, 'deleted_at', None) is not None:
            return False

    # -------------------------------------------------------------------------
    # RULE 6: Viewer Role Absolute Restriction on Access Management
    # Rationale: By platform design, users with the 'viewer' role can NEVER manage
    # access or grant permissions to others under any circumstances, even if they
    # are recorded as the owner of a document.
    # -------------------------------------------------------------------------
    if user.role == 'viewer' and action == 'manage_access':
        return False

    # -------------------------------------------------------------------------
    # RULE 7: Administrator Privileges within Own Organization
    # Rationale: Administrators have full administrative authority over their own
    # tenant. They can manage all users, inspect audit logs, and access or manage
    # all active documents belonging to their organization.
    # -------------------------------------------------------------------------
    if user.role == 'admin':
        return True

    # -------------------------------------------------------------------------
    # RULE 8: Document Owner Privileges
    # Rationale: The creator/owner of a document is granted full control to view,
    # download, edit, delete, and delegate access to their uploaded document.
    # (Note: Viewers managing access was already filtered out by Rule 6).
    # -------------------------------------------------------------------------
    if document is not None and document.owner_id == user.id:
        if action in {'view', 'download', 'edit', 'delete', 'manage_access'}:
            return True

    # -------------------------------------------------------------------------
    # RULE 8A: Document Upload Privilege
    # Rationale: Only admins and owners can upload documents. Viewers cannot upload.
    # -------------------------------------------------------------------------
    if action == 'upload':
        return user.role in {'admin', 'owner'}

    # -------------------------------------------------------------------------
    # RULE 9: Delegated Access Grants for Non-Owners / Viewers
    # Rationale: Non-owners can only interact with a document if an active,
    # non-revoked AccessGrant exists for them.
    # - 'read' or 'edit' grant allows: view, download.
    # - 'edit' grant allows: edit.
    # - Delegated users can NEVER delete documents or manage access.
    # -------------------------------------------------------------------------
    if document is not None:
        if action in {'delete', 'manage_access'}:
            return False

        grant = _get_active_grant(user, document)
        if grant is not None:
            if action in {'view', 'download'} and grant.permission in {'read', 'edit'}:
                return True
            if action == 'edit' and grant.permission == 'edit':
                return True

    # -------------------------------------------------------------------------
    # RULE 10: Default Deny
    # Rationale: Any action not explicitly permitted above (e.g. non-admins
    # attempting 'manage_users' or 'view_audit') is strictly denied by default.
    # -------------------------------------------------------------------------
    return False


def require(action: str, document=None):
    """
    Authorization helper and route decorator that enforces `can()` and aborts
    with HTTP 403 Forbidden if denied.

    Usage as a route helper:
        require('view', document)
        require('manage_users')

    Usage as a route decorator:
        @require('manage_users')
        def view_users():
            ...

        @require('view', document)
        def view_doc(document):
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            doc = document
            # If document was not provided at decoration time, look up in route kwargs
            if doc is None and 'document' in kwargs:
                doc = kwargs['document']
            elif doc is None and 'document_id' in kwargs:
                from app.models import Document
                doc = Document.query.get(kwargs['document_id'])

            if not can(current_user, action, doc):
                abort(403)
            return fn(*args, **kwargs)
        return decorated_view

    # When called directly inside an active HTTP request context as a statement:
    if has_request_context():
        if not can(current_user, action, document):
            abort(403)
        return decorator

    # When used as a decorator at import time:
    return decorator
