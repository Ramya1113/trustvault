"""
Audit logging engine for TrustVault.

CRITICAL SECURITY REQUIREMENTS:
1. Append-Only: AuditLog entries must never be modified or deleted.
2. Tamper-Evident Hash Chaining: Each audit entry contains a cryptographic SHA-256
   hash formed by combining the previous entry's hash (within the same organization)
   with the current entry's fields (prev_hash + org_id + actor_id + action +
   target + outcome + detail + created_at).
3. Chain Verification: `verify_chain(org_id)` recomputes and validates every link
   in an organization's audit trail, returning (ok, first_broken_id).
"""

from datetime import datetime, timezone
import hashlib
import threading
from flask import has_request_context, request
from extensions import db
from app.models import AuditLog, User

# Concurrency Control: Per-Organization thread locks
# Serializes hash calculation and audit log appending per tenant,
# preventing race conditions where concurrent requests read the same prev_hash.
_org_locks = {}
_meta_lock = threading.Lock()


def _get_org_lock(org_id: int) -> threading.Lock:
    """Retrieve or create a thread lock dedicated to a specific organization."""
    with _meta_lock:
        if org_id not in _org_locks:
            _org_locks[org_id] = threading.Lock()
        return _org_locks[org_id]


def compute_entry_hash(prev_hash, org_id, actor_id, action, target_type, target_id,
                       outcome, detail, created_at):
    """
    Calculate the SHA-256 hash for an audit log entry.

    Formula:
        SHA-256(prev_hash + org_id + actor_id + action + target + outcome + detail + created_at)

    Args:
        prev_hash (str or None): Hash of the immediately preceding entry in this org.
        org_id (int): ID of the organization (tenant).
        actor_id (int or None): ID of the user performing the action.
        action (str): Action name (e.g. 'auth.login', 'document.view').
        target_type (str or None): Entity type affected (e.g. 'document', 'user').
        target_id (int or None): Entity ID affected.
        outcome (str): 'allowed' or 'denied'.
        detail (str or None): Textual context or parameters.
        created_at (datetime or str): Timestamp of the audit event.

    Returns:
        str: Hex-encoded 64-character SHA-256 digest.
    """
    if hasattr(created_at, 'strftime'):
        # Normalize timezone to UTC naive so formatting is identical across SQLite/Postgres and Python objects
        if getattr(created_at, 'tzinfo', None) is not None:
            created_at = created_at.astimezone(timezone.utc).replace(tzinfo=None)
        created_at_str = created_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
    else:
        created_at_str = str(created_at)

    target_str = f"{target_type or ''}:{target_id or ''}" if (target_type or target_id) else ""

    raw_data = (
        f"{prev_hash or ''}"
        f"{org_id}"
        f"{actor_id or ''}"
        f"{action}"
        f"{target_str}"
        f"{outcome}"
        f"{detail or ''}"
        f"{created_at_str}"
    )
    return hashlib.sha256(raw_data.encode('utf-8')).hexdigest()


def log_event(actor, action: str, target_type=None, target_id=None,
              outcome: str = "allowed", detail: str = None, org_id=None):
    """
    Append a tamper-evident, hash-chained event to the AuditLog table.

    Args:
        actor (User or int or None): The user performing the action, their ID, or None.
        action (str): The action performed (e.g. 'auth.login', 'auth.logout').
        target_type (str, optional): Target entity type (e.g. 'user', 'document').
        target_id (int, optional): ID of the target entity.
        outcome (str, optional): 'allowed' or 'denied'. Defaults to 'allowed'.
        detail (str, optional): Additional context or error details.
        org_id (int, optional): Organization ID override if actor is None or int.

    Returns:
        AuditLog: The persisted audit log record.
    """
    # 1. Resolve actor_id and org_id
    actor_id = None
    event_org_id = org_id

    if isinstance(actor, User):
        actor_id = actor.id
        if event_org_id is None:
            event_org_id = actor.org_id
    elif isinstance(actor, int):
        actor_id = actor
    elif actor is not None and hasattr(actor, 'id'):
        actor_id = actor.id
        if event_org_id is None and hasattr(actor, 'org_id'):
            event_org_id = actor.org_id

    if event_org_id is None:
        raise ValueError("Cannot log audit event: an organization ID (org_id) is required.")

    # 2. Capture client IP address if inside an active HTTP request
    ip_address = request.remote_addr if has_request_context() else None

    # 3. Create UTC timestamp (normalized to UTC naive for consistent database storage)
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # 4-6. Acquire per-organization lock to serialize hash chaining and commit
    org_lock = _get_org_lock(event_org_id)
    with org_lock:
        # 4. Find the previous audit entry within the SAME organization
        # The chain is scoped per tenant (organization)
        last_entry = (
            AuditLog.query
            .filter_by(org_id=event_org_id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        prev_hash = last_entry.entry_hash if last_entry else None

        # 5. Compute cryptographic SHA-256 hash for this new entry
        entry_hash = compute_entry_hash(
            prev_hash=prev_hash,
            org_id=event_org_id,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            detail=detail,
            created_at=created_at
        )

        # 6. Append entry to the database (Append-Only)
        entry = AuditLog(
            org_id=event_org_id,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            ip_address=ip_address,
            detail=detail,
            created_at=created_at,
            prev_hash=prev_hash,
            entry_hash=entry_hash
        )
        db.session.add(entry)
        db.session.commit()

        return entry


def verify_chain(org_id: int):
    """
    Verify the cryptographic integrity of the audit log chain for an organization.

    Iterates through all audit records for the given org_id in chronological order:
    1. Checks that each entry's `prev_hash` matches the preceding entry's `entry_hash`.
    2. Recomputes `entry_hash` from the record's raw fields and asserts exact match.

    Args:
        org_id (int): Organization ID whose audit chain to verify.

    Returns:
        tuple (bool, int or None):
            (True, None) if the chain is intact and valid.
            (False, first_broken_id) if any record was modified, deleted, or inserted out of order.
    """
    entries = (
        AuditLog.query
        .filter_by(org_id=org_id)
        .order_by(AuditLog.id.asc())
        .all()
    )

    if not entries:
        return True, None

    expected_prev_hash = None

    for entry in entries:
        # Check 1: Does the entry's recorded prev_hash match the expected hash of the prior entry?
        if entry.prev_hash != expected_prev_hash:
            return False, entry.id

        # Check 2: Does the entry_hash match the recomputed hash of its stored data?
        recomputed_hash = compute_entry_hash(
            prev_hash=entry.prev_hash,
            org_id=entry.org_id,
            actor_id=entry.actor_id,
            action=entry.action,
            target_type=entry.target_type,
            target_id=entry.target_id,
            outcome=entry.outcome,
            detail=entry.detail,
            created_at=entry.created_at
        )

        if entry.entry_hash != recomputed_hash:
            return False, entry.id

        # Advance pointer
        expected_prev_hash = entry.entry_hash

    return True, None
