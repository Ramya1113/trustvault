# TrustVault

**TrustVault** is a secure, multi-tenant document-sharing platform built with simplicity, safety, and strict tenancy isolation at its core. It is engineered with Python and Flask, utilizing server-side authorization, database BLOB storage, and a tamper-evident, append-only, SHA-256 hash-chained audit log.

---

## 1. What It Is

TrustVault allows organizations (tenants) to store, manage, and securely share confidential documents with complete privacy:
- **Strict Multi-Tenancy:** Every user belongs to exactly one Organization. No data, queries, or access checks ever cross tenant boundaries.
- **Centralized Server-Side Authorization:** All authorization rules are strictly evaluated in a single function (`app/permissions.py`). The application never relies on UI button hiding for security.
- **Tamper-Evident Audit Trail:** Every sensitive action—including **denied access attempts**—is permanently recorded in a cryptographic SHA-256 hash chain that can be validated at any time.
- **Database BLOB File Storage:** Files are stored directly as binary payloads inside the database (up to 5 MB), guaranteeing atomic transactional commits and eliminating orphaned files.

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

- **Authentication & Tenant Onboarding (`app/blueprints/auth.py`):**
  - Registration automatically creates a new Organization and makes the registrant its initial `admin`.
  - Passwords require $\ge 10$ characters, securely hashed with Werkzeug (`pbkdf2`/`scrypt`).
  - Brute-force protection: Rate-limiting locks an account for 10 minutes after 5 consecutive failed login attempts (HTTP 429).
  - Generic error messages prevent username enumeration.
  - Session cookies enforce `HttpOnly` and `SameSite=Lax`.

- **Document Management (`app/blueprints/documents.py`):**
  - Upload allowed only for `admin` and `owner` roles.
  - Strict extension allowlist (`pdf`, `docx`, `xlsx`, `txt`, `png`, `jpg`, `jpeg`).
  - File size restricted to $\le 5$ MB.
  - Automatic SHA-256 integrity calculation and BLOB storage.
  - Version increments (`v+1`) when replacing document content.
  - Secure downloads serving `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
  - Soft-delete archiving (`deleted_at`).
  - Search filter by title, description, or filename.

- **Document Sharing & Access Delegation (`app/blueprints/sharing.py`):**
  - Document owners and admins can delegate `read` or `edit` access to active colleagues in the **same organization**.
  - Cross-tenant grant attempts and duplicate active grants are rejected.
  - Update permissions between `read` and `edit`.
  - Revocation sets `revoked_at` timestamp, taking effect **immediately on the very next request**.

- **Tamper-Evident Audit Logging (`app/audit.py`):**
  - Append-only database table.
  - Cryptographic hash chaining: each entry stores `prev_hash` and `entry_hash = SHA-256(prev_hash + org_id + actor_id + action + target + outcome + detail + created_at)`.
  - SQLAlchemy ORM event listeners block all `UPDATE` and `DELETE` operations on audit logs.
  - Cryptographic verification engine (`verify_chain(org_id)`) validates the chain from genesis to latest record and pinpoints any broken entry.

- **Admin Console (`app/blueprints/admin.py`):**
  - Member roster: create users with roles (`admin`, `owner`, `viewer`), deactivate/reactivate accounts, change roles.
  - **Safety Rules:** An administrator cannot demote or deactivate the last active admin in the organization.
  - Audit trail viewer with multi-criteria filters (action, actor, outcome, target type, search query).
  - One-click **"Verify Chain"** button with status banner.
  - Organization-wide document repository with metrics and deleted document viewer.

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
   flask init-db
   ```

5. **Seed demo data (creates Acme Corp with admin, owner, viewer, and sample file):**
   ```bash
   flask seed
   ```

6. **Start the local development server:**
   ```bash
   python run.py
   ```
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 5. Running the Test Suite

TrustVault includes a comprehensive test suite of 167 automated tests covering permissions, authentication, models, document lifecycles, hash chaining, sharing, and integration scenarios:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test modules
pytest tests/test_permissions.py
pytest tests/test_integration.py
pytest tests/test_audit.py
```

---

## 6. How to Deploy (Render)

TrustVault is pre-configured for instant deployment on [Render](https://render.com) with [`render.yaml`](file:///d:/trustvault/render.yaml), [`Procfile`](file:///d:/trustvault/Procfile), and [`build.sh`](file:///d:/trustvault/build.sh).

### Option A: One-Click Blueprint Deployment (Recommended)
1. Push your repository to GitHub.
2. In the Render Dashboard, click **New +** $\rightarrow$ **Blueprint**.
3. Select your repository. Render automatically configures:
   - Web Service with Gunicorn (`gunicorn run:app`)
   - Managed PostgreSQL database (`trustvault-db`)
   - Environment variables (`SECRET_KEY`, `DATABASE_URL`)
   - Build command (`./build.sh`, which runs `pip install` and `flask init-db`)
4. Click **Apply**.
5. After deployment, open the web service **Shell** tab and run:
   ```bash
   flask seed
   ```

### Option B: Manual Setup
1. Create a **PostgreSQL** database on Render (`trustvault-db`).
2. Create a **Web Service** connected to your repository:
   - **Build Command:** `./build.sh` (or `pip install -r requirements.txt && flask init-db`)
   - **Start Command:** `gunicorn run:app`
   - **Environment Variables:**
     - `DATABASE_URL`: Your PostgreSQL Internal Connection String.
     - `SECRET_KEY`: A secure random 64-character secret.
     - `PYTHON_VERSION`: `3.10.9`
3. In the Render Shell, run `flask seed` to seed demo users.

---

## 7. Demo Accounts

The `flask seed` command populates the database with these pre-configured accounts:

| Role | Username | Password | Email | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `demo_admin` | `AdminPassword123!` | `admin@acme.demo` | Full organization management, audit logs, all documents |
| **Owner** | `demo_owner` | `OwnerPassword123!` | `owner@acme.demo` | Uploads documents, manages access grants & revocations |
| **Viewer** | `demo_viewer` | `ViewerPassword123!` | `viewer@acme.demo` | Accesses only documents explicitly shared with them |

*Organization:* `Acme Corporation`  
*Pre-loaded document:* `"Welcome to TrustVault Guide"` (owned by `demo_owner`, shared with `demo_viewer` as read-only).

---

## 8. Known Limitations

1. **5 MB File Size Limit:** Files are capped at 5 MB to ensure database BLOB queries remain fast and lightweight.
2. **Relational Database Storage Only:** Files are stored as SQL BLOBs rather than external object storage (S3/GCS).
3. **Single Tenant per User:** Users belong to exactly one Organization; multi-organization switching is intentionally not supported.
4. **In-Memory Login Lockout Tracker:** The rate-limiting tracker resides in application memory and resets on server restart. For multi-node load-balanced deployments, an external cache (e.g. Redis) would replace the in-memory dictionary.
5. **SQLite Naive Datetimes:** Local SQLite stores dates as strings without timezone offsets; the audit system normalizes timestamps to UTC naive strings (`%Y-%m-%dT%H:%M:%S.%f`) to guarantee identical SHA-256 hash reproduction between local SQLite and production PostgreSQL.

---

## 9. Design Choices

### Files Stored Directly in the Database (BLOBs)
- **Transactional Consistency:** Storing document metadata, version history, and raw binary bytes in the same database table ensures that uploads and edits are completely atomic. If a transaction fails or rolls back, no orphan files linger on disk.
- **Backup Simplicity:** Database dumps (`pg_dump` or SQLite copy) capture all files, metadata, user permissions, and audit logs simultaneously.
- **Access Gating:** Files cannot be accessed through static web server URL paths or directory traversals. Every single byte is served through Flask streaming with verified permissions.

### Tamper-Evident Hash Chaining
- **Cryptographic Auditability:** Rather than relying on standard database logs, TrustVault chains every audit record to the preceding entry using SHA-256 (`prev_hash + data`).
- **Detection of Modification & Deletion:** If an attacker modifies or deletes a database row directly via SQL, `verify_chain(org_id)` immediately detects that the recorded hash no longer matches the recomputed digest and reports the exact ID where the chain was broken.
- **Strictly Scoped by Tenant:** Each organization maintains its own isolated hash chain starting from its own genesis event (e.g., registration or initial seed).

### Interpretation of User Roles
- **Admin (Organization Steward):** Holds full administrative authority within their own tenant to audit compliance, manage users, and view/delete documents. To prevent administrative lockout, the system prevents an admin from deactivating or demoting the organization's sole active admin.
- **Owner (Creator & Delegator):** Holds complete authority over the intellectual property they upload. They control who can view or edit their files and can revoke delegated access at any moment.
- **Viewer (Least-Privilege Consumer):** Can only access documents explicitly delegated to them. Under platform Rule 6, a viewer can never grant or manage permissions, preventing privilege escalation.
