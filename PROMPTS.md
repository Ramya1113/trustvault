# TrustVault: Engineering Prompts & AI Correction Log

This document records the honest development history of TrustVault: where the AI assistant made incorrect assumptions or introduced flaws, how each issue was caught, and what was changed to fix it.

Each entry follows the format:
**What I asked → What the AI got wrong → How it was found → What was changed**

---

## AI Corrections & Fixes

### 1. Cross-Tenant Sharing Vulnerability
- **What I asked:** Build `app/blueprints/sharing.py` to allow document owners and admins to grant read or edit permissions to other users in the same organization.
- **What the AI got wrong:** The initial sharing logic looked up the target recipient user by primary key ID without verifying that the target user actually belonged to the caller's organization (`target_user.org_id == current_user.org_id`). This would have allowed a user to share private documents with accounts in another company.
- **How it was found:** The automated test `test_cannot_grant_access_to_cross_tenant_user` in `tests/test_sharing.py` attempted to share a document with an out-of-tenant user and caught that the endpoint accepted the request instead of rejecting it.
- **What was changed:** Added strict server-side tenant validation in `grant_access()`: if `target_user.org_id != current_user.org_id`, the request immediately aborts with a 404 / error and logs a denied attempt.

### 2. Admin Test Failures on First Run
- **What I asked:** Build `app/blueprints/admin.py` for user management, audit inspection with chain verification, and org-wide documents, along with comprehensive tests.
- **What the AI got wrong:** The test suite for the admin module had mismatched assumptions about form redirect paths, flash message text, and user setup fixtures, causing multiple tests to fail on the first run.
- **How it was found:** Running `pytest tests/test_admin.py` immediately failed with assertion errors and route redirection mismatches.
- **What was changed:** Fixed test fixtures, aligned expected status codes, corrected form submission targets and assertions, and ensured admin safety checks (preventing demoting or deactivating the last active admin) were properly exercised and passing.

### 3. Missing Audit Entry for Organization Registration
- **What I asked:** Wire `log_event()` into authentication events so all tenant actions are auditable.
- **What the AI got wrong:** Login, logout, and failed login attempts were logged, but the registration route (`/auth/register`) created the organization and admin user without recording an audit event. The genesis of every new organization had no audit record.
- **How it was found:** An end-to-end integration test (`test_integration_register_creates_org_and_admin`) checked the audit table after tenant creation and found zero rows.
- **What was changed:** Added `log_event(actor=user, action="auth.register", target_type="organization", ...)` right after committing the new organization, establishing the first hash entry in each tenant's audit trail.

### 4. Duplicate `extensions.py` Module
- **What I asked:** Centralize Flask extension instances (`db`, `login_manager`, `csrf`) to prevent circular import loops.
- **What the AI got wrong:** The AI created `extensions.py` in the project root, but also created a duplicate file `app/extensions.py` that simply re-exported the same objects. This created ambiguity about which file was the canonical source of truth.
- **How it was found:** Project code review revealed two identical extension files. Grepping imports confirmed nothing in the codebase relied on `app.extensions`.
- **What was changed:** Deleted `app/extensions.py`, standardized all imports on root `extensions.py`, and added `tests/test_extensions_structure.py` to ensure the duplicate never returns.

### 5. Missing `FLASK_APP` in Render Deployment Configuration
- **What I asked:** Configure the repository for deployment to Render using `render.yaml` and a build script.
- **What the AI got wrong:** The initial `render.yaml` and `build.sh` omitted `FLASK_APP=run.py`. When Render builds the project and executes `flask init-db`, Flask cannot locate the application factory without an explicit app target, which would cause the deployment to crash.
- **How it was found:** Review of `render.yaml` and running Flask CLI commands in a clean shell showed Flask failed with `Could not locate a Flask application`.
- **What was changed:** Added `export FLASK_APP=run.py` to `build.sh`, changed commands to `flask --app run.py init-db` and `flask --app run.py seed`, added `FLASK_APP=run.py` to `render.yaml`, and pinned `startCommand` to `gunicorn --workers 1 --threads 4 run:app`. Verified in `tests/test_render_config.py`.

### 6. Login Timing Leak for Unknown Usernames
- **What I asked:** Handle failed logins for unknown usernames securely without disclosing whether the user exists.
- **What the AI got wrong:** While the UI error message was generic ("Invalid username or password"), existing accounts ran `user.check_password()` which executes an expensive cryptographic hash calculation (~50-100ms), whereas unknown usernames returned immediately (~1ms). An attacker measuring response times could enumerate valid usernames based on response latency.
- **How it was found:** Code review of the `login()` endpoint in `app/blueprints/auth.py` showed that `user is None` skipped the password hashing check entirely.
- **What was changed:** Generated a constant dummy password hash (`_DUMMY_PASSWORD_HASH`) at startup. When `user is None`, `check_password_hash(_DUMMY_PASSWORD_HASH, password)` is executed so execution timing is identical regardless of whether the account exists. Added tests in `tests/test_auth_unknown_login.py`.

### 7. Missing Magic-Byte Validation for DOCX and XLSX Uploads
- **What I asked:** Enforce magic-byte validation to stop attackers from renaming executables or scripts to allowed document extensions.
- **What the AI got wrong:** The AI added signature checks for PDF, PNG, and JPG, but left DOCX and XLSX checking only file extension strings. An attacker could upload an executable disguised as `document.docx`.
- **How it was found:** Reviewing `_validate_magic_bytes()` showed that `docx` and `xlsx` fell through to `return True` without inspecting binary headers.
- **What was changed:** Added magic-byte verification for the standard ZIP/OpenXML signature `PK\x03\x04` for both DOCX and XLSX files. Documented that `.txt` files contain raw arbitrary plaintext and cannot have a fixed magic byte signature. Verified in `tests/test_magic_bytes_upload.py`.

### 8. Verification of the Per-Organization Audit Lock
- **What I asked:** Ensure audit logging is concurrency-safe under multi-threaded load so two simultaneous events do not corrupt the hash chain.
- **What the AI got wrong:** Initially assumed database transactions alone would prevent race conditions. Without an in-process lock, two threads could query the same `prev_hash` simultaneously before committing, creating two entries with identical parent hashes and breaking the chain.
- **How it was found:** To test if the lock was actually doing anything, I temporarily removed the lock (`with org_lock:`) in `app/audit.py` and ran the concurrent test with two threads logging 15 events each. The test immediately failed: only 28 of 30 entries were recorded, and the cryptographic chain broke.
- **What was changed:** Restored `with _get_org_lock(actor.org_id):` in `app/audit.py`. The test passed with all 30 entries cleanly chained and 100% verified. Renamed to `tests/test_audit_concurrency.py`.

---

## What I Verified Myself

1. **Local Server Execution:** Started the development server on `http://127.0.0.1:5000` and confirmed that the health check (`/healthz`) returns HTTP 200 `{"status": "ok"}`.
2. **Demo Account Authentication:** Verified logging in with each of the three seeded demo accounts (`demo_admin`, `demo_owner`, `demo_viewer`) in `Acme Corporation`.
3. **Role Enforcement in Action:** Confirmed that `demo_viewer` cannot upload documents or view unauthorized files, while `demo_owner` can upload and delegate access, and `demo_admin` can view all documents and inspect audit logs.
4. **Tamper Detection:** Confirmed that modifying a single database row directly in SQLite causes `verify_chain()` to immediately flag the tampering and identify the broken row ID.
5. **CSRF Protection:** Verified with `WTF_CSRF_ENABLED = True` that state-changing POST requests without a valid CSRF token return HTTP 400 Bad Request.
6. **No Secrets Tracked:** Checked `git ls-files` and confirmed that no `.env`, `.venv`, `instance/`, or `*.db` files are tracked in git.
7. **Complete Test Suite:** Ran all 195 automated pytest integration and unit tests, achieving a 100% pass rate.

---

## Known Limits

1. **In-Process Thread Lock Scope:** The audit lock (`_get_org_lock`) uses Python's `threading.Lock`. It serializes threads within a single Python process (which is why Gunicorn is pinned to `--workers 1 --threads 4`). For multi-process workers (`--workers > 1`) or multi-instance clusters, database-level row locking (`SELECT ... FOR UPDATE`) or a dedicated sequencer queue is required.
2. **In-Memory Lockout Storage:** The failed login lockout tracker resides in application memory. In a multi-server setup, an external store like Redis would be required.
3. **5 MB File Size Limit:** Files are capped at 5 MB to keep relational BLOB storage performant.
4. **Relational BLOB Storage:** Files are stored directly in SQL rather than cloud object storage (S3/GCS).
5. **Plaintext Files (.txt):** Plaintext files have no universal binary header and cannot be verified via magic bytes; they are validated by file extension and character safety.
6. **Full-Chain Rewrites by Root DBAs:** A privileged database administrator with raw SQL write access who alters a row and recalculates all subsequent hashes could produce an internally consistent chain. True immutability against database administrators requires periodic external anchoring to a write-once ledger or external timestamping authority.
