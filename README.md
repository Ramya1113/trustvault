# TrustVault

**TrustVault** is a secure, multi-tenant document-sharing web application built with Python and Flask. Designed for confidentiality and strict data isolation, it features centralized server-side authorization, database BLOB file storage with SHA-256 integrity verification, and an append-only, tamper-evident audit trail backed by cryptographic hash chaining.

---

## Live Deployment

- **Live URL:** [https://trustvault-jrjm.onrender.com](https://trustvault-jrjm.onrender.com)
- **Note on Free-Tier Hosting:** The live deployment is hosted on Render's free tier. When inactive, the web service spins down into a dormant state. The **first page load can take about 50 seconds** while the server instance spins back up. Subsequent requests respond normally.

---

## Demo Accounts

The live site and local seed command come pre-loaded with sample accounts for the **Acme Corporation** organization:

| Role | Username | Password | Email | Access Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `demo_admin` | `AdminPassword123!` | `admin@acme.demo` | Full organization administration, user management, audit inspection |
| **Owner** | `demo_owner` | `OwnerPassword123!` | `owner@acme.demo` | Uploads documents, manages read/edit access grants and revocations |
| **Viewer** | `demo_viewer` | `ViewerPassword123!` | `viewer@acme.demo` | Accesses only documents explicitly shared with them |

> [!WARNING]
> The demo passwords above are for test data and evaluation only. **Never upload real, confidential, proprietary, or personal documents to the demo site.**

*Pre-loaded Sample Document:* `"Welcome to TrustVault Guide"` (owned by `demo_owner`, shared with `demo_viewer` as read-only).

---

## Role & Permission Matrix

All access decisions are enforced server-side in [`app/permissions.py`](file:///d:/trustvault/app/permissions.py) using `can()` and `require()`. The application never relies on UI button hiding for security:

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

> **Key Enforcement Rule (Rule 6):** Users with the `viewer` role can **never** manage document access or grant permissions to others, even if they were the uploader of a document.

---

## Local Setup & Execution

### Prerequisites
- Python 3.10+
- Git

### Exact Setup Commands

#### Windows (PowerShell)
```powershell
# 1. Clone the repository and enter the directory
git clone https://github.com/Ramya1113/trustvault.git
cd trustvault

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database schema
flask --app run.py init-db

# 5. Seed demo organization and accounts (idempotent)
flask --app run.py seed

# 6. Start development server
python run.py
```
Open `http://127.0.0.1:5000` in your browser.

#### macOS / Linux (Bash)
```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/Ramya1113/trustvault.git
cd trustvault

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database schema
flask --app run.py init-db

# 5. Seed demo organization and accounts (idempotent)
flask --app run.py seed

# 6. Start development server
python run.py
```
Open `http://127.0.0.1:5000` in your browser.

---

## Running the Test Suite

TrustVault includes a comprehensive automated test suite verifying multi-tenancy isolation, permissions, cryptographic audit chaining, magic-byte file signature validation, CSRF defense, and session invalidation.

To run the test suite:
```bash
pytest -q
```

### Real Test Results
```text
240 passed in 60.40s
```

### Targeted Test Commands
```bash
# Authorization matrix (Role x Action x Ownership x Grants)
pytest tests/test_permissions.py

# Cryptographic hash chain verification and tamper detection
pytest tests/test_audit.py

# Multi-threaded concurrent audit logging safety
pytest tests/test_audit_concurrency.py

# Binary magic-byte signatures and file extension allowlist
pytest tests/test_magic_bytes_upload.py

# Timing attack mitigation, log sanitization, and lockout caps
pytest tests/test_auth_unknown_login.py

# Memory optimization verifying BLOB deferral in listing queries
pytest tests/test_document_defer.py

# CSRF protection on state-changing POST endpoints
pytest tests/test_csrf_protection.py

# Ten threat defenses (sessions, soft deletes, form tampering, headers, redirects)
pytest tests/test_threat_defences.py
```

---

## How to Deploy on Render

TrustVault is pre-configured for automated deployment on [Render](https://render.com) using [`render.yaml`](file:///d:/trustvault/render.yaml), [`Procfile`](file:///d:/trustvault/Procfile), and [`build.sh`](file:///d:/trustvault/build.sh).

### Production Server Command: `--workers 1 --threads 4`
In [`Procfile`](file:///d:/trustvault/Procfile) and [`render.yaml`](file:///d:/trustvault/render.yaml), Gunicorn is configured as:
```bash
gunicorn --workers 1 --threads 4 run:app
```
- **Thread-Safe Audit Hash Chaining:** TrustVault serializes audit log entry creation per organization using in-process Python thread locks (`_get_org_lock`). Running a single worker process ensures all concurrent requests share the same process memory, guaranteeing that `prev_hash` queries and hash chaining are serialized per tenant.
- **Shared In-Memory Rate Limiting:** The failed-login tracker (`_failed_login_attempts`) is maintained in memory. A single worker ensures all authentication attempts hit the same tracking dictionary without requiring external infrastructure like Redis.
- **Concurrent I/O:** 4 worker threads allow the application to handle multiple concurrent I/O operations simultaneously (file downloads, database queries) with minimal memory footprint on the Render free tier.

### Deployment Steps via Render Blueprint
1. Push your repository to GitHub.
2. In the Render Dashboard, click **New +** $\rightarrow$ **Blueprint**.
3. Select your repository. Render automatically provisions:
   - **Web Service:** Runs Gunicorn (`gunicorn --workers 1 --threads 4 run:app`).
   - **Managed PostgreSQL Database:** `trustvault-db`.
   - **Build Command:** `bash build.sh` (installs dependencies and runs `flask --app run.py init-db`).
   - **Environment Variables:**
     - `PYTHON_VERSION=3.10.9`
     - `FLASK_APP=run.py`
     - `SEED_DEMO=1` (triggers idempotent demo account seeding during build).
     - `SECRET_KEY` (auto-generated cryptographically secure secret).
     - `DATABASE_URL` (automatically linked to PostgreSQL instance).
4. Click **Apply**.

---

## Key Design Choices

### 1. Files Stored Directly in Database (BLOBs)
- **Transactional Consistency:** Storing document metadata, version history, and raw binary bytes in the same database table ensures uploads and updates are atomic. If a transaction fails or rolls back, no orphaned files remain on disk.
- **Unified Backups:** Database dumps (`pg_dump` or SQLite copy) capture all files, metadata, user permissions, and audit logs simultaneously.
- **Access Gating & Memory Safety:** Files are never served as static web assets. Every download is gated by permissions, serving `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. To prevent memory exhaustion, `defer(Document.data)` prevents binary payloads from loading during listing and search queries.

### 2. Tamper-Evident SHA-256 Hash Chaining
- **Cryptographic Auditability:** Rather than relying on simple database rows, TrustVault chains every audit record to the preceding entry using SHA-256 (`prev_hash + fields -> entry_hash`).
- **Detection of Modification & Deletion:** If a row is modified or deleted directly in the database, [`verify_chain(org_id)`](file:///d:/trustvault/app/audit.py) detects the hash mismatch and identifies the exact broken record ID.
- **Tenant Scoping:** Each organization maintains its own isolated hash chain starting from its own genesis event.

### 3. Centralized Server-Side Authorization
- **Single Source of Truth:** All access logic is unified in [`can()`](file:///d:/trustvault/app/permissions.py) and [`require()`](file:///d:/trustvault/app/permissions.py).
- **Rule 4 Checked First:** Multi-tenant boundaries are verified before any role or ownership checks: `if document.org_id != user.org_id: return False`.

### 4. Timing Equalization on Authentication
- **Dummy Hash Verification:** For non-existent usernames, [`login()`](file:///d:/trustvault/app/blueprints/auth.py) executes a dummy password hash check (`_DUMMY_PASSWORD_HASH`) to ensure identical latency to existing accounts, eliminating timing-based username enumeration.

---

## Known Limits & Architectural Boundaries

1. **In-Memory Lockout Resets on Server Restart:** The failed login rate limiter (`_failed_login_attempts`) is stored in Python memory. Restarting or redeploying the web server resets the lockout tracker.
2. **One-Worker Lock Scope for Audit Trail:** Per-tenant audit serialization relies on Python's in-memory `threading.Lock`. Running multiple worker processes (`--workers > 1`) across separate OS processes or containers would require database row locks (`SELECT ... FOR UPDATE` or advisory locks) or an asynchronous queue to prevent race conditions.
3. **DBA Hash Chain Recomputation:** An attacker with root database access can alter rows and recalculate all downstream SHA-256 hashes. Defending against full-chain rewrites requires external cryptographic anchoring (e.g. write-once storage or digital timestamping).
4. **5 MB File Size Ceiling:** Uploads are capped at 5 MB to keep database BLOB operations fast and memory-efficient.
5. **Single Tenant per User:** Users belong to exactly one Organization; multi-organization switching is intentionally not supported.
6. **No Email Verification:** Organization registration does not verify mailbox ownership.
7. **No Multi-Factor Authentication (MFA / 2FA):** User authentication relies solely on username and password.
8. **No Malware / Antivirus Scanning:** Files are checked for allowed extensions and binary magic numbers, but are not analyzed for executable exploits or macros via ClamAV.
9. **Plaintext Files Accepted Without Signature Verification:** Plain text (`.txt`) files lack standardized magic numbers and are accepted based on extension without signature inspection.
10. **No Self-Service Password Reset:** Password recovery must be handled manually by an organization administrator.
11. **Client-Side Cookie Session Storage:** Flask sessions are signed with `SECRET_KEY` on client-side cookies; individual session IDs cannot be revoked server-side while keeping the user account active.
