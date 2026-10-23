"""
SQLAlchemy models for TrustVault.

This module defines the database schema for multi-tenant isolation, user identity,
document storage (as BLOBs), role-based and document-level access grants, and
tamper-evident, hash-chained audit logging.

Models:
- Organization: Tenant boundary. Every user and document belongs to one organization.
- User: Identity with assigned role (admin, owner, viewer) within an organization.
- Document: File uploaded to an organization, stored as raw binary (BLOB) data.
- AccessGrant: Explicit permissions (read or edit) granted to users for specific documents.
- AuditLog: Append-only, hash-chained event record tracking allowed and denied actions.
"""

from datetime import datetime, timezone
import hashlib
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event
from extensions import db


def utc_now():
    """Helper returning current timestamp in UTC timezone."""
    return datetime.now(timezone.utc)


class Organization(db.Model):
    """
    Represents an Organization (Tenant).

    Multi-Tenancy Rule:
    Every user and document belongs strictly to one organization.
    Data must never leak or be queried across different organizations.
    """
    __tablename__ = 'organizations'

    # Primary key identifier for the organization
    id = db.Column(db.Integer, primary_key=True)

    # Human-readable, unique organization name (e.g., 'Acme Corp')
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)

    # Timestamp when the organization was created
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships to other models within this tenant
    users = db.relationship('User', backref='organization', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('Document', backref='organization', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='organization', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Organization id={self.id} name='{self.name}'>"


class User(UserMixin, db.Model):
    """
    Represents an authenticated user within a specific Organization.

    Roles:
    - 'admin': Manages users in their own org; accesses and manages all documents in own org.
    - 'owner': Uploads documents; grants/revokes read/edit access on documents they uploaded.
    - 'viewer': Can only view documents explicitly shared with them; cannot manage access.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # Foreign key to the user's organization (strict single-tenant association)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    # Unique username for login and display
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    # Unique email address
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # Securely hashed password (never store plaintext passwords)
    password_hash = db.Column(db.String(255), nullable=False)

    # User role within the organization: 'admin', 'owner', or 'viewer'
    role = db.Column(db.String(20), nullable=False, default='viewer')

    # Account status flag: False disables login
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Timestamp when the user account was created
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    # Documents uploaded by this user
    uploaded_documents = db.relationship(
        'Document',
        foreign_keys='Document.owner_id',
        backref='owner',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    # Access grants received by this user
    access_grants = db.relationship(
        'AccessGrant',
        foreign_keys='AccessGrant.user_id',
        backref='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    # Access grants created/granted by this user
    granted_accesses = db.relationship(
        'AccessGrant',
        foreign_keys='AccessGrant.granted_by',
        backref='granter',
        lazy='dynamic'
    )

    __table_args__ = (
        # Ensure role is always one of the three supported roles
        db.CheckConstraint("role IN ('admin', 'owner', 'viewer')", name='ck_user_role'),
    )

    def set_password(self, password):
        """Hashes the plaintext password using pbkdf2/scrypt and stores the hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies a plaintext password against the stored password hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}' role='{self.role}' org_id={self.org_id}>"


class Document(db.Model):
    """
    Represents an uploaded document stored inside the database.

    Key Requirements:
    - Files are stored directly as BLOBs in the database (`data`).
    - Maximum file size: 5 MB (enforced at upload).
    - Soft delete: documents are not deleted immediately; `deleted_at` is set instead.
    """
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)

    # Tenant boundary: document belongs to exactly one organization
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    # The user who originally uploaded the document
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Metadata
    title = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False, default='application/octet-stream')

    # Size of the binary data in bytes
    size = db.Column(db.Integer, nullable=False)

    # Cryptographic SHA-256 hash of the binary file content for integrity checks
    sha256 = db.Column(db.String(64), nullable=False, index=True)

    # The raw file content stored as binary BLOB in the database
    data = db.Column(db.LargeBinary, nullable=False)

    # Document version counter, incremented when updated
    version = db.Column(db.Integer, default=1, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Soft delete timestamp: NULL means active, set timestamp means deleted
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    # Relationships
    access_grants = db.relationship('AccessGrant', backref='document', lazy='dynamic', cascade='all, delete-orphan')

    __table_args__ = (
        # Composite index for filtering non-deleted documents within an organization
        db.Index('ix_documents_org_deleted', 'org_id', 'deleted_at'),
    )

    @property
    def is_deleted(self):
        """Returns True if the document has been soft-deleted."""
        return self.deleted_at is not None

    def __repr__(self):
        return f"<Document id={self.id} title='{self.title}' org_id={self.org_id} owner_id={self.owner_id}>"


class AccessGrant(db.Model):
    """
    Represents an explicit permission granted to a user on a specific document.

    Permissions:
    - 'read': Can view/download the document.
    - 'edit': Can modify/update the document.

    Constraints:
    - Only ONE active grant per (document_id, user_id) pair.
    - Revocation is soft: `revoked_at` is set, preserving audit history.
    """
    __tablename__ = 'access_grants'

    id = db.Column(db.Integer, primary_key=True)

    # Target document being shared
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False, index=True)

    # User receiving the permission
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Permission level: 'read' or 'edit'
    permission = db.Column(db.String(20), nullable=False)

    # User who granted this access (owner or admin)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Timestamp when access was granted
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    # Timestamp when access was revoked (NULL = grant is currently active)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    __table_args__ = (
        # Permission must be either 'read' or 'edit'
        db.CheckConstraint("permission IN ('read', 'edit')", name='ck_access_grant_permission'),

        # Partial unique index: ensures at most ONE active grant (revoked_at IS NULL) per document and user
        db.Index(
            'uq_active_document_user_grant',
            'document_id',
            'user_id',
            unique=True,
            postgresql_where=db.text('revoked_at IS NULL'),
            sqlite_where=db.text('revoked_at IS NULL')
        ),
    )

    @property
    def is_active(self):
        """Returns True if this grant has not been revoked."""
        return self.revoked_at is None

    def revoke(self):
        """Revokes the access grant by setting the revoked_at timestamp."""
        self.revoked_at = utc_now()

    def __repr__(self):
        return (f"<AccessGrant id={self.id} doc={self.document_id} user={self.user_id} "
                f"perm='{self.permission}' active={self.is_active}>")


class AuditLog(db.Model):
    """
    Represents an append-only, tamper-evident audit record.

    Key Requirements:
    - Every sensitive action must be logged, including DENIED attempts.
    - Uses cryptographic hash chaining: each entry includes `prev_hash` (hash of previous entry)
      and `entry_hash` (SHA-256 of this entry's contents combined with `prev_hash`).
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)

    # Tenant boundary
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    # The user performing the action (NULL for unauthenticated or system actions)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)

    # Action name (e.g., 'document.view', 'document.upload', 'access.grant', 'auth.login')
    action = db.Column(db.String(100), nullable=False, index=True)

    # Entity type affected (e.g., 'document', 'user', 'access_grant')
    target_type = db.Column(db.String(50), nullable=True)

    # Identifier of the affected entity
    target_id = db.Column(db.Integer, nullable=True)

    # Outcome of authorization or operation: 'allowed' or 'denied'
    outcome = db.Column(db.String(20), nullable=False, index=True)

    # Client IP address
    ip_address = db.Column(db.String(45), nullable=True)

    # Detailed context or metadata (e.g. JSON string or description)
    detail = db.Column(db.Text, nullable=True)

    # Timestamp of the event
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Cryptographic hash of the immediately preceding audit log entry in the organization
    prev_hash = db.Column(db.String(64), nullable=True)

    # Cryptographic hash of this entry (SHA-256)
    entry_hash = db.Column(db.String(64), nullable=False)

    actor = db.relationship('User', foreign_keys=[actor_id], backref='audit_actions')

    __table_args__ = (
        # Outcome constraint
        db.CheckConstraint("outcome IN ('allowed', 'denied')", name='ck_audit_log_outcome'),
        # Composite index for querying audit events chronologically within a tenant
        db.Index('ix_audit_logs_org_created', 'org_id', 'created_at'),
    )

    @staticmethod
    def calculate_entry_hash(prev_hash, org_id, actor_id, action, target_type, target_id,
                             outcome, ip_address, detail, created_at_iso):
        """
        Calculate SHA-256 hash of the audit entry fields.

        Combining all critical fields with the previous entry's hash forms an
        unbreakable cryptographic chain (Merkle/blockchain-style hash chaining).
        """
        payload = {
            'prev_hash': prev_hash or 'GENESIS',
            'org_id': org_id,
            'actor_id': actor_id,
            'action': action,
            'target_type': target_type,
            'target_id': target_id,
            'outcome': outcome,
            'ip_address': ip_address,
            'detail': detail,
            'created_at': created_at_iso
        }
        # Serialize with sorted keys to ensure deterministic representation
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def __repr__(self):
        return (f"<AuditLog id={self.id} org={self.org_id} action='{self.action}' "
                f"outcome='{self.outcome}' hash='{self.entry_hash[:8]}...'>")


# -----------------------------------------------------------------------------
# Append-Only Enforcers
# -----------------------------------------------------------------------------
@event.listens_for(AuditLog, 'before_update')
def prevent_audit_log_update(mapper, connection, target):
    """Enforce append-only integrity: AuditLog entries must never be modified."""
    raise RuntimeError("AuditLog is append-only: modifying audit log entries is strictly forbidden.")


@event.listens_for(AuditLog, 'before_delete')
def prevent_audit_log_delete(mapper, connection, target):
    """Enforce append-only integrity: AuditLog entries must never be deleted."""
    raise RuntimeError("AuditLog is append-only: deleting audit log entries is strictly forbidden.")
