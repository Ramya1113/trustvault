"""
Documents Blueprint for TrustVault.

Handles document listing, uploading, viewing details, downloading, editing,
and soft deletion.

Security & Architectural Requirements:
1. Upload allowed ONLY for 'admin' and 'owner' roles.
2. File extension allowlist: pdf, docx, xlsx, txt, png, jpg, jpeg.
3. Max file size: 5 MB (enforced on upload and version replacement).
4. Raw bytes stored directly in the database as LargeBinary.
5. Content integrity verified via SHA-256 hash.
6. EVERY route looks up document by id AND org_id and calls permissions.require().
7. Consistent 404 (or 403) for documents users cannot access.
8. Every action, including DENIED attempts, is recorded in the hash-chained audit log.
9. Download headers enforce Content-Disposition: attachment and X-Content-Type-Options: nosniff.
"""

from datetime import datetime, timezone
import hashlib
import io
import mimetypes
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, abort, send_file
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from extensions import db
from app.models import Document, AccessGrant
from app.permissions import can, require
from app.audit import log_event
from app.forms import DocumentUploadForm, DocumentEditForm

docs_bp = Blueprint('documents', __name__, url_prefix='/documents')

# File validation constraints
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'txt', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 Megabytes


def _is_allowed_extension(filename: str) -> bool:
    """Check if the filename has an allowlisted extension."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


def _get_document_or_abort(doc_id: int, action: str):
    """
    Look up a document scoped to the current user's organization and enforce permissions.

    Security Rules:
    - Must match both document id AND current_user.org_id.
    - Soft-deleted documents return 404.
    - If document does not exist within the tenant, returns 404 (and logs cross-tenant probe if applicable).
    - If document exists but user lacks authorization, logs the denied attempt and calls require(action, doc) to abort with 403.
    """
    doc = Document.query.filter_by(
        id=doc_id,
        org_id=current_user.org_id,
        deleted_at=None
    ).first()

    if doc is None:
        # Check if the ID exists in another organization to audit cross-tenant probing
        other_tenant_doc = db.session.get(Document, doc_id)
        if other_tenant_doc is not None and other_tenant_doc.org_id != current_user.org_id:
            log_event(
                actor=current_user,
                action=f"document.{action}",
                target_type="document",
                target_id=doc_id,
                outcome="denied",
                detail="Cross-tenant document access attempt blocked"
            )
        abort(404)

    # Server-side authorization check via centralized permissions module
    if not can(current_user, action, doc):
        log_event(
            actor=current_user,
            action=f"document.{action}",
            target_type="document",
            target_id=doc.id,
            outcome="denied",
            detail=f"Unauthorized {action} attempt on document '{doc.title}'"
        )
        require(action, doc)  # Enforces 403 Forbidden abort

    return doc


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@docs_bp.route('/', methods=['GET'])
@login_required
def list_documents():
    """
    List active documents visible to the current user within their organization.
    - Admins see all documents in their organization.
    - Owners see documents they own PLUS documents shared with them.
    - Viewers see only documents shared with them via an active AccessGrant.
    - Supports title search filtering via ?q=<search_term>.
    """
    search_query = request.args.get('q', '').strip()

    # Select statement for active (non-revoked) grants belonging to the current user
    active_grants_select = (
        db.select(AccessGrant.document_id)
        .filter(
            AccessGrant.user_id == current_user.id,
            AccessGrant.revoked_at.is_(None)
        )
    )

    # Base query: strictly scoped to current user's organization and non-deleted
    base_query = Document.query.filter(
        Document.org_id == current_user.org_id,
        Document.deleted_at.is_(None)
    )

    if current_user.role == 'admin':
        # Admin can view all documents in own org
        docs_query = base_query
    elif current_user.role == 'owner':
        # Owner sees docs they uploaded OR docs shared with them
        docs_query = base_query.filter(
            db.or_(
                Document.owner_id == current_user.id,
                Document.id.in_(active_grants_select)
            )
        )
    else:
        # Viewer sees only documents explicitly shared with them
        docs_query = base_query.filter(Document.id.in_(active_grants_select))

    # Apply title search filter if provided
    if search_query:
        docs_query = docs_query.filter(Document.title.ilike(f"%{search_query}%"))

    documents = docs_query.order_by(Document.created_at.desc()).all()

    # Log listing action
    log_event(
        actor=current_user,
        action="document.list",
        target_type="document",
        target_id=None,
        outcome="allowed",
        detail=f"Listed documents (count: {len(documents)}, search: '{search_query}')"
    )

    return render_template('documents/list.html', documents=documents, search_query=search_query)


@docs_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """
    Upload a new document into the user's organization vault.
    Strictly restricted to 'admin' and 'owner' roles.
    """
    # Enforce upload authorization: denied for viewers
    if not can(current_user, 'upload', None):
        log_event(
            actor=current_user,
            action="document.upload",
            target_type="document",
            target_id=None,
            outcome="denied",
            detail=f"Upload blocked: role '{current_user.role}' is not authorized to upload"
        )
        require('upload')  # Aborts with 403 Forbidden

    form = DocumentUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        raw_filename = file.filename or 'unnamed'
        filename = secure_filename(raw_filename) or 'document.bin'

        # Validate file extension against allowlist
        if not _is_allowed_extension(filename):
            flash(
                "Invalid file type. Allowed extensions: pdf, docx, xlsx, txt, png, jpg, jpeg.",
                "danger"
            )
            return render_template('documents/upload.html', form=form)

        # Read binary data
        file_bytes = file.read()
        file_size = len(file_bytes)

        # Validate file size
        if file_size == 0:
            flash("Cannot upload an empty file.", "danger")
            return render_template('documents/upload.html', form=form)

        if file_size > MAX_FILE_SIZE:
            flash("File size exceeds maximum allowed limit of 5 MB.", "danger")
            return render_template('documents/upload.html', form=form)

        # Compute SHA-256 hash for binary integrity
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Guess MIME type
        mime_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

        # Create Document record
        doc = Document(
            org_id=current_user.org_id,
            owner_id=current_user.id,
            title=form.title.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            filename=filename,
            mime_type=mime_type,
            size=file_size,
            sha256=sha256_hash,
            data=file_bytes,
            version=1
        )
        db.session.add(doc)
        db.session.commit()

        # Audit log the upload
        log_event(
            actor=current_user,
            action="document.upload",
            target_type="document",
            target_id=doc.id,
            outcome="allowed",
            detail=f"Uploaded '{doc.filename}' ({doc.size} bytes, sha256={doc.sha256[:8]}...)"
        )

        flash(f"Document '{doc.title}' uploaded successfully.", "success")
        return redirect(url_for('documents.detail', doc_id=doc.id))

    return render_template('documents/upload.html', form=form)


@docs_bp.route('/<int:doc_id>', methods=['GET'])
@login_required
def detail(doc_id: int):
    """
    View document details, metadata, and accessible actions.
    """
    doc = _get_document_or_abort(doc_id, 'view')

    # Audit log the view event
    log_event(
        actor=current_user,
        action="document.view",
        target_type="document",
        target_id=doc.id,
        outcome="allowed",
        detail=f"Viewed metadata for '{doc.title}' (version {doc.version})"
    )

    # Compute permission flags for UI buttons
    can_download = can(current_user, 'download', doc)
    can_edit = can(current_user, 'edit', doc)
    can_delete = can(current_user, 'delete', doc)
    can_manage_access = can(current_user, 'manage_access', doc)

    return render_template(
        'documents/detail.html',
        doc=doc,
        can_download=can_download,
        can_edit=can_edit,
        can_delete=can_delete,
        can_manage_access=can_manage_access
    )


@docs_bp.route('/<int:doc_id>/download', methods=['GET'])
@login_required
def download(doc_id: int):
    """
    Download the binary payload of a document.
    Enforces Content-Disposition: attachment, correct mime type, and X-Content-Type-Options: nosniff.
    """
    doc = _get_document_or_abort(doc_id, 'download')

    # Audit log the download
    log_event(
        actor=current_user,
        action="document.download",
        target_type="document",
        target_id=doc.id,
        outcome="allowed",
        detail=f"Downloaded '{doc.filename}' ({doc.size} bytes)"
    )

    response = send_file(
        io.BytesIO(doc.data),
        mimetype=doc.mime_type,
        as_attachment=True,
        download_name=doc.filename
    )

    # Security headers required by specification
    response.headers['Content-Disposition'] = f'attachment; filename="{doc.filename}"'
    response.headers['X-Content-Type-Options'] = 'nosniff'

    return response


@docs_bp.route('/<int:doc_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(doc_id: int):
    """
    Edit document metadata (title, description) or upload a new version.
    Increments version number when a new file is uploaded.
    """
    doc = _get_document_or_abort(doc_id, 'edit')

    form = DocumentEditForm()

    if request.method == 'GET':
        form.title.data = doc.title
        form.description.data = doc.description

    if form.validate_on_submit():
        doc.title = form.title.data.strip()
        doc.description = form.description.data.strip() if form.description.data else None

        new_file = form.file.data
        version_incremented = False

        if new_file and getattr(new_file, 'filename', ''):
            raw_filename = new_file.filename
            filename = secure_filename(raw_filename) or doc.filename

            # Validate extension
            if not _is_allowed_extension(filename):
                flash(
                    "Invalid file type. Allowed extensions: pdf, docx, xlsx, txt, png, jpg, jpeg.",
                    "danger"
                )
                return render_template('documents/edit.html', form=form, doc=doc)

            file_bytes = new_file.read()
            file_size = len(file_bytes)

            if file_size == 0:
                flash("Cannot upload an empty file as a new version.", "danger")
                return render_template('documents/edit.html', form=form, doc=doc)

            if file_size > MAX_FILE_SIZE:
                flash("File size exceeds maximum allowed limit of 5 MB.", "danger")
                return render_template('documents/edit.html', form=form, doc=doc)

            # Update document content and metadata
            doc.filename = filename
            doc.mime_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            doc.size = file_size
            doc.data = file_bytes
            doc.sha256 = hashlib.sha256(file_bytes).hexdigest()
            doc.version += 1
            version_incremented = True

        doc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()

        # Audit log the edit
        detail_msg = (
            f"Updated metadata and uploaded version {doc.version}"
            if version_incremented
            else f"Updated metadata for version {doc.version}"
        )
        log_event(
            actor=current_user,
            action="document.edit",
            target_type="document",
            target_id=doc.id,
            outcome="allowed",
            detail=detail_msg
        )

        flash("Document updated successfully.", "success")
        return redirect(url_for('documents.detail', doc_id=doc.id))

    return render_template('documents/edit.html', form=form, doc=doc)


@docs_bp.route('/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete(doc_id: int):
    """
    Soft-delete a document by setting deleted_at timestamp.
    """
    doc = _get_document_or_abort(doc_id, 'delete')

    # Soft-delete the document
    doc.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()

    # Audit log the deletion
    log_event(
        actor=current_user,
        action="document.delete",
        target_type="document",
        target_id=doc.id,
        outcome="allowed",
        detail=f"Soft-deleted document '{doc.title}' (version {doc.version})"
    )

    flash(f"Document '{doc.title}' has been deleted.", "info")
    return redirect(url_for('documents.list_documents'))
