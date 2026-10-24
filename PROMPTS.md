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
- **How it was found:** Claude pointed out that Flask only auto-detects `app.py` or `wsgi.py`, so `flask init-db` on Render would fail without `FLASK_APP`.
- **What was changed:** Added `export FLASK_APP=run.py` to `build.sh`, changed commands to `flask --app run.py init-db` and `flask --app run.py seed`, added `FLASK_APP=run.py` to `render.yaml`, and pinned `startCommand` to `gunicorn --workers 1 --threads 4 run:app`. Verified in `tests/test_render_config.py`.

### 6. Login Timing Leak for Unknown Usernames
- **What I asked:** Handle failed logins for unknown usernames securely without disclosing whether the user exists.
- **What the AI got wrong:** While the UI error message was generic ("Invalid username or password"), existing accounts ran `user.check_password()` which executes an expensive cryptographic hash calculation (~50-100ms), whereas unknown usernames returned immediately (~1ms). An attacker measuring response times could enumerate valid usernames based on response latency.
- **How it was found:** Claude pointed out that unknown usernames skip the password hash, so response time reveals which usernames exist.
- **What was changed:** Generated a constant dummy password hash (`_DUMMY_PASSWORD_HASH`) at startup. When `user is None`, `check_password_hash(_DUMMY_PASSWORD_HASH, password)` is executed so execution timing is identical regardless of whether the account exists. Added tests in `tests/test_auth_unknown_login.py`.

### 7. Missing Magic-Byte Validation for DOCX and XLSX Uploads
- **What I asked:** Enforce magic-byte validation to stop attackers from renaming executables or scripts to allowed document extensions.
- **What the AI got wrong:** The AI added signature checks for PDF, PNG, and JPG, but left DOCX and XLSX checking only file extension strings. An attacker could upload an executable disguised as `document.docx`.
- **How it was found:** Claude pointed out that docx and xlsx only had extension checks and no content checks.
- **What was changed:** Added magic-byte verification for the standard ZIP/OpenXML signature `PK\x03\x04` for both DOCX and XLSX files. Documented that `.txt` files contain raw arbitrary plaintext and cannot have a fixed magic byte signature. Verified in `tests/test_magic_bytes_upload.py`.

### 8. Verification of the Per-Organization Audit Lock
- **What I asked:** Ensure audit logging is concurrency-safe under multi-threaded load so two simultaneous events do not corrupt the hash chain.
- **What the AI got wrong:** The first version of `log_event` had no locking at all, so concurrent requests could create two entries with the same previous hash.
- **How it was found:** Claude pointed out that `log_event` reads the previous hash and then inserts, so two concurrent requests can both read the same previous hash. I then had the lock temporarily removed, and the concurrency test failed with only 28 of 30 entries, and passed after the lock was restored.
- **What was changed:** Restored `with _get_org_lock(actor.org_id):` in `app/audit.py`. The test passed with all 30 entries cleanly chained and 100% verified. Renamed to `tests/test_audit_concurrency.py`.

---

## How I Used Two AIs

Antigravity generated the code from my step-by-step prompts, and Claude was used to plan the prompts and review Antigravity's summaries for security and deployment problems. I read the results and ran the live checks listed below.

---

## What I Verified Myself

1. **Local App Testing:** Personally tested the local application running on `http://127.0.0.1:5000` as viewer, owner, and admin.
2. **Audit Tamper Detection:** The automated test modifies an audit row directly in the database and `verify_chain` detects it (I did not edit the database by hand).
3. **Automated Test Suite:** Ran all 195 automated pytest integration and unit tests, achieving a 100% pass rate.

---

## Live Deployment Checks

The following checks were personally performed on the live production deployment at https://trustvault-jrjm.onrender.com:

1. **Company Registration:** Registered a company (`KITS GUNTUR`) on the live site.
2. **Admin Authentication:** Logged in as the administrator of `KITS GUNTUR` on the live site.
3. **Audit Trail Inspection:** Opened the Audit Trail in the live admin console.
4. **Cryptographic Chain Verification:** Clicked "Verify chain" on the live site: result was **OK** (verified on the live PostgreSQL database on 24 Oct 2026).

---

## Known Limits

1. **In-Process Thread Lock Scope:** The audit lock (`_get_org_lock`) uses Python's `threading.Lock`. It serializes threads within a single Python process (which is why Gunicorn is pinned to `--workers 1 --threads 4`). For multi-process workers (`--workers > 1`) or multi-instance clusters, database-level row locking (`SELECT ... FOR UPDATE`) or a dedicated sequencer queue is required.
2. **In-Memory Lockout Storage:** The failed login lockout tracker resides in application memory. In a multi-server setup, an external store like Redis would be required.
3. **Lockout Reset on Render Free Tier:** The in-memory login lockout resets whenever the Render free-tier service restarts or sleeps.
4. **Database Scope of Chain Verification:** The audit chain was tested on SQLite by the test suite and checked on the live Postgres database only as stated in "Live deployment checks".
5. **5 MB File Size Limit:** Files are capped at 5 MB to keep relational BLOB storage performant.
6. **Relational BLOB Storage:** Files are stored directly in SQL rather than cloud object storage (S3/GCS).
7. **Plaintext Files (.txt):** Plaintext files have no universal binary header and cannot be verified via magic bytes; they are validated by file extension and character safety.
8. **Full-Chain Rewrites by Root DBAs:** A privileged database administrator with raw SQL write access who alters a row and recalculates all subsequent hashes could produce an internally consistent chain. True immutability against database administrators requires periodic external anchoring to a write-once ledger or external timestamping authority.
