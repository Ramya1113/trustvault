# TrustVault

**TrustVault** is a secure, multi-tenant document-sharing platform built with simplicity, safety, and strict tenancy isolation at its core. It is engineered with Python and Flask, utilizing server-side authorization, database BLOB storage, and a tamper-evident, append-only, SHA-256 hash-chained audit log.

---

## 1. What It Is

TrustVault allows organizations (tenants) to store, manage, and securely share confidential documents with complete privacy:
- **Strict Multi-Tenancy:** Every user belongs to exactly one Organization. No data, queries, or access checks ever cross tenant boundaries.
- **Centralized Server-Side Authorization:** All authorization rules are strictly evaluated in a single function ([`app/permissions.py`](file:///d:/trustvault/app/permissions.py)). The application never relies on UI button hiding for security.
- **Tamper-Evident Audit Trail:** Every sensitive action—including **denied access attempts**—is permanently recorded in a cryptographic SHA-256 hash chain that can be validated at any time.
- **Database BLOB File Storage:** Files are stored directly as binary payloads inside the database (up to 5 MB), guaranteeing atomic transactional commits and eliminating orphaned files.
- **Memory Optimization:** Binary BLOB data is deferred (`defer(Document.data)`) during document listing and search queries to conserve RAM.

---

## 2. Role & Permission Matrix

The platform enforces three distinct user roles with strict separation of duties:

| Action | Admin | Document Owner | Delegated User (`edit` grant) | Delegated User (`read` grant) | Viewer (No Grant) | Cross-Tenant User |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Upload Document** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| **View Document Details** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **Download Document** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **Edit Metadata / Version** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Delete Document (Soft)** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| **Manage Access (Grant/Revoke)** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No *(Rule 6)* | ❌ No |
| **Manage Organization Users** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **View & Verify Audit Trail** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |

> **Key Rule (Rule 6):** Users with the `viewer` role can **never** manage document access or grant permissions to others, even if they were the uploader of a document.

---

## 3. Working Features

- **Authentication & Tenant Onboarding ([`app/blueprints/auth.py`](file:///d:/trustvault/app/blueprints/auth.py)):**
  - Registration automatically creates a new Organization and makes the registrant its initial `admin`.
  - Passwords require $\ge 10$ characters, securely hashed with Werkzeug (`pbkdf2`/`scrypt`).
  - Brute-force protection: Rate-limiting locks an account for 10 minutes after 5 consecutive failed login attempts (HTTP 429).
  - **Equalized Execution Timing:** Non-existent usernames execute a dummy password hash check (`_DUMMY_PASSWORD_HASH`) to ensure identical server response latency to existing accounts, eliminating timing-based username enumeration.
  - **Memory Capping & Expiration:** The lockout dictionary automatically expires stale records and is capped at `MAX_LOCKOUT_ENTRIES = 10000` to prevent memory exhaustion DoS.
  - **Log Injection Defense:** Usernames in security log lines are sanitized against CRLF characters (`\r`, `\n`) and truncated to 64 characters.
  - Generic error messages prevent username enumeration on bad login attempts.
  - Failed logins for unknown usernames trigger rate-limiting identically and are logged to `current_app.logger.warning` with client IP and username without polluting tenant audit logs.
  - Session cookies enforce `HttpOnly` and `SameSite=Lax`.
  - All state-changing forms enforce Flask-WTF CSRF validation (missing or invalid token returns HTTP 400).

- **Document Management ([`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py)):**
  - Upload allowed only for `admin` and `owner` roles.
  - Strict extension allowlist (`pdf`, `docx`, `xlsx`, `txt`, `png`, `jpg`, `jpeg`).
  - Filenames sanitized via `secure_filename`.
  - **Magic-Byte File Signatures:** Binary file signatures verified on upload and edit:
    - PDF: `b'%PDF-'`
    - PNG: `b'\x89PNG\r\n\x1a\n'`
    - JPG/JPEG: `b'\xff\xd8\xff'`
    - DOCX/XLSX: `b'PK\x03\x04'` (standard OpenXML Zip container signature)
    - *Note on Plain Text:* Plain text (`.txt`) files contain raw arbitrary plaintext and are intentionally not content-checked against a binary magic number because plain text has no uniform file signature.
  - Authoritative MIME type mapping (`EXTENSION_MIME_MAP`) overrides client-supplied content types.
  - File size restricted to $\le 5$ MB.
  - Automatic SHA-256 integrity calculation and BLOB storage.
  - Version increments (`v+1`) when replacing document content.
  - Secure downloads serving `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
  - Memory-optimized listing queries utilizing `defer(Document.data)`.
  - Soft-delete archiving (`deleted_at`).
  - Search filter by title, description, or filename.

- **Document Sharing & Access Delegation ([`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py)):**
  - Document owners and admins can delegate `read` or `edit` access to active colleagues in the **same organization**.
  - Cross-tenant grant attempts and duplicate active grants are rejected.
  - Update permissions between `read` and `edit`.
  - Revocation sets `revoked_at` timestamp, taking effect **immediately on the very next request**.

- **Tamper-Evident Audit Logging ([`app/audit.py`](file:///d:/trustvault/app/audit.py)):**
  - Append-only database table.
  - Per-tenant thread locks (`_get_org_lock`) ensure safe concurrent logging across threads.
  - Cryptographic hash chaining: each entry stores `prev_hash` and `entry_hash = SHA-256(prev_hash + org_id + actor_id + action + target + outcome + detail + created_at)`.
  - SQLAlchemy ORM event listeners block all `UPDATE` and `DELETE` operations on audit logs.
  - Cryptographic verification engine (`verify_chain(org_id)`) validates the chain from genesis to latest record and pinpoints any broken entry.

- **Admin Console ([`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py)):**
  - Member roster: create users with roles (`admin`, `owner`, `viewer`), deactivate/reactivate accounts, change roles.
  - **Safety Rules:** An administrator cannot demote or deactivate the last active admin in the organization.
  - Audit trail viewer with multi-criteria filters (action, actor, outcome, target type, search query).
  - One-click **"Verify Chain"** button with status banner.
  - Organization-wide document repository with metrics and memory-efficient `defer(Document.data)` queries.

- **Health Monitoring:**
  - Health check endpoint at `/healthz` returning `{"status": "ok"}` with HTTP 200.

---

## 4. Local Setup & Execution

### Prerequisites
- Python 3.10+
- Git

### Exact Setup Commands

1. **Clone the repository and enter the directory:**
   ```bash
   git clone <repo-url> trustvault
   cd trustvault
   ```

2. **Create and activate a Python virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize database tables:**
   ```bash
   flask --app run.py init-db
   ```

5. **Seed demo data (idempotent, safe to run multiple times):**
   ```bash
   flask --app run.py seed
   ```

6. **Start the local development server:**
   ```bash
   python run.py
   ```
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 5. Running the Test Suite

TrustVault includes a comprehensive test suite of automated tests organized by behavioral domain:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific behavioral test suites
pytest tests/test_permissions.py          # Authorization matrix (Role x Action x Ownership x Grants)
pytest tests/test_audit_concurrency.py    # Concurrency-safe hash chaining under multi-threaded load
pytest tests/test_csrf_protection.py      # CSRF enforcement (token presence and validity)
pytest tests/test_magic_bytes_upload.py   # Upload extension allowlist and binary magic byte checks
pytest tests/test_document_defer.py       # Memory optimization verifying BLOB deferral on lists
pytest tests/test_auth_unknown_login.py   # Timing equalization, log sanitization, and lockout caps
pytest tests/test_seed_idempotent.py      # Idempotent database seeding and SEED_DEMO=1 triggers
pytest tests/test_render_config.py        # Production deployment build configs and WSGI entry points
```

---

## 6. How to Deploy (Render)

TrustVault is pre-configured for deployment on [Render](https://render.com) using [`render.yaml`](file:///d:/trustvault/render.yaml), [`Procfile`](file:///d:/trustvault/Procfile), and [`build.sh`](file:///d:/trustvault/build.sh).

### Production Server Architecture: Why `--workers 1 --threads 4`?
In [`Procfile`](file:///d:/trustvault/Procfile) and [`render.yaml`](file:///d:/trustvault/render.yaml), Gunicorn is explicitly pinned to:
```bash
gunicorn --workers 1 --threads 4 run:app
```
**Why this design decision?**
1. **Thread-Safe Cryptographic Audit Serialization:** TrustVault serializes audit log entry creation per organization using in-process Python thread locks (`_get_org_lock`). Running a single worker process ensures all concurrent requests share the same process memory, guaranteeing that `prev_hash` queries and hash chaining are strictly serialized per tenant.
2. **Shared Brute-Force Rate Limiting:** The failed-login tracker (`_failed_login_attempts`) is maintained in memory. A single worker ensures all authentication attempts hit the same tracking dictionary without requiring an external cache like Redis.
3. **High Concurrency via Multi-Threading:** Utilizing 4 worker threads allows the application to handle multiple concurrent I/O operations simultaneously (such as file streaming and database queries) with minimal memory footprint on the Render free tier.

### Automated Setup via Render Blueprint
1. Push your repository to GitHub.
2. In the Render Dashboard, click **New +** $\rightarrow$ **Blueprint**.
3. Select your repository. Render automatically configures:
   - Web Service with Gunicorn (`gunicorn --workers 1 --threads 4 run:app`)
   - Managed PostgreSQL database (`trustvault-db`)
   - Normalized `DATABASE_URL` handling (`postgres://` automatically translated to `postgresql://`)
   - Build command (`bash build.sh`, which installs requirements and executes `flask --app run.py init-db`)
   - Environment variables:
     - `FLASK_APP=run.py`
     - `SEED_DEMO=1` (automatically runs idempotent demo seeding during build, ideal since Render free tier does not provide a web shell)
     - `SECRET_KEY` (auto-generated)
4. Click **Apply**.

---

## 7. Demo Accounts

The `flask seed` command (or setting `SEED_DEMO=1`) populates the database with these pre-configured accounts:

| Role | Username | Password | Email | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `demo_admin` | `AdminPassword123!` | `admin@acme.demo` | Full organization management, audit logs, all documents |
| **Owner** | `demo_owner` | `OwnerPassword123!` | `owner@acme.demo` | Uploads documents, manages access grants & revocations |
| **Viewer** | `demo_viewer` | `ViewerPassword123!` | `viewer@acme.demo` | Accesses only documents explicitly shared with them |

*Organization:* `Acme Corporation`  
*Pre-loaded document:* `"Welcome to TrustVault Guide"` (owned by `demo_owner`, shared with `demo_viewer` as read-only).

---

## 8. Known Limitations & Audit-Chain Limits

1. **5 MB File Size Limit:** Files are capped at 5 MB to ensure database BLOB queries remain fast and lightweight.
2. **Relational Database Storage Only:** Files are stored as SQL BLOBs rather than external object storage (S3/GCS).
3. **Single Tenant per User:** Users belong to exactly one Organization; multi-organization switching is intentionally not supported.
4. **Single-Worker Process Model:**
   - Because audit locks and lockout dictionaries use in-process thread synchronization, running multiple worker processes (`--workers > 1`) across separate OS processes or distributed container instances would require database-level locking (`SELECT ... FOR UPDATE` or advisory locks) and a shared cache (e.g. Redis).
5. **Direct SQL Tampering vs. Chain Rewrites:**
   - The hash chain detects modifications or deletions made to existing records. However, an attacker with full root access to the PostgreSQL database who modifies a row and then recomputes all subsequent entry hashes could produce an internally consistent chain. External anchoring (such as periodic checkpointing to an immutable write-once store) is necessary to defend against full-history rewrites.
6. **Unknown User Probes:**
   - Because `AuditLog` requires a non-null tenant `org_id`, failed logins for non-existent usernames are not recorded in tenant audit chains. They are logged to standard application security logs (`current_app.logger.warning`) to avoid polluting tenant logs with external attacker noise.

---

## 9. Design Choices

### Files Stored Directly in the Database (BLOBs)
- **Transactional Consistency:** Storing document metadata, version history, and raw binary bytes in the same database table ensures that uploads and edits are completely atomic. If a transaction fails or rolls back, no orphan files linger on disk.
- **Backup Simplicity:** Database dumps (`pg_dump` or SQLite copy) capture all files, metadata, user permissions, and audit logs simultaneously.
- **Access Gating & Memory Safety:** Files cannot be accessed through static web server URL paths. Every single byte is served through Flask streaming with verified permissions. To prevent memory bloat, `defer(Document.data)` prevents binary payloads from being loaded during roster and search queries.

### Tamper-Evident Hash Chaining
- **Cryptographic Auditability:** Rather than relying on standard database logs, TrustVault chains every audit record to the preceding entry using SHA-256 (`prev_hash + data`).
- **Detection of Modification & Deletion:** If an attacker modifies or deletes a database row directly via SQL, `verify_chain(org_id)` immediately detects that the recorded hash no longer matches the recomputed digest and reports the exact ID where the chain was broken.
- **Strictly Scoped by Tenant:** Each organization maintains its own isolated hash chain starting from its own genesis event (e.g., registration or initial seed).

### Interpretation of User Roles
- **Admin (Organization Steward):** Holds full administrative authority within their own tenant to audit compliance, manage users, and view/delete documents. To prevent administrative lockout, the system prevents an admin from deactivating or demoting the organization's sole active admin.
- **Owner (Creator & Delegator):** Holds complete authority over the intellectual property they upload. They control who can view or edit their files and can revoke delegated access at any moment.
- **Viewer (Least-Privilege Consumer):** Can only access documents explicitly delegated to them. Under platform Rule 6, a viewer can never grant or manage permissions, preventing privilege escalation.
