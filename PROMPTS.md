# TrustVault: Engineering Prompts & AI Correction Log

PROMPTS.md was written up after the build from my build log, and the dates are the commit dates.

This document records the honest development history of TrustVault: where the AI assistant made incorrect assumptions or introduced flaws, how each issue was caught, and what was changed to fix it.

Each entry includes its commit date, a link to the commit on GitHub, category tags, and four lines:
- **What I asked**
- **What the tool produced**
- **What was wrong**
- **What I did instead**

---

## AI Corrections & Fixes

### 1. Cross-Tenant Sharing Vulnerability
- **Category:** Authorisation & Access Control
- **Date:** 2026-10-23
- **Commit:** [63ef434](https://github.com/Ramya1113/trustvault/commit/63ef434)
- **What I asked:** Build `app/blueprints/sharing.py` to allow document owners and admins to grant read or edit permissions to other users in the same organization.
- **What the tool produced:** A sharing route that looked up target recipient users by primary key ID without verifying that the target user belonged to the caller's organization.
- **What was wrong:** A user could grant read or edit access on their organization's documents to a user belonging to a completely different tenant company.
- **What I did instead:** Added strict server-side tenant validation (`target_user.org_id == current_user.org_id`) in `grant_access()` so out-of-tenant requests are denied and logged, verified by `test_cannot_grant_access_to_cross_tenant_user` in `tests/test_sharing.py`.

### 2. Admin Test Failures on First Run
- **Category:** Testing & Tenant Administration
- **Date:** 2026-10-23
- **Commit:** [63ef434](https://github.com/Ramya1113/trustvault/commit/63ef434)
- **What I asked:** Build `app/blueprints/admin.py` for user management, audit inspection with chain verification, and org-wide documents, along with comprehensive tests.
- **What the tool produced:** An admin test suite with mismatched assumptions about form redirect paths, flash message categories, and user setup fixtures.
- **What was wrong:** Running `pytest tests/test_admin.py` failed on the first run with assertion errors and route redirection mismatches.
- **What I did instead:** Corrected test fixtures, aligned expected status codes, fixed form submission targets and assertions, and confirmed admin safety checks (preventing demoting or deactivating the last active admin) pass cleanly.

### 3. Missing Audit Entry for Organization Registration
- **Category:** Audit Trail
- **Date:** 2026-10-23
- **Commit:** [d16acd4](https://github.com/Ramya1113/trustvault/commit/d16acd4)
- **What I asked:** Wire `log_event()` into authentication events so all tenant actions are recorded in the audit trail.
- **What the tool produced:** Authentication logging that covered login, logout, and failed login attempts, but omitted registration (`/auth/register`).
- **What was wrong:** Creating a brand new organization and initial administrator left zero rows in the audit log, omitting the genesis record of the tenant.
- **What I did instead:** Added `log_event(actor=user, action="auth.register", target_type="organization", ...)` in `register()`, establishing the genesis hash entry in each tenant's audit trail, verified by `test_integration_register_creates_org_and_admin` in `tests/test_integration.py`.

### 4. Duplicate `extensions.py` Module
- **Category:** Codebase Structure
- **Date:** 2026-10-23
- **Commit:** [1fd8474](https://github.com/Ramya1113/trustvault/commit/1fd8474)
- **What I asked:** Centralize Flask extension instances (`db`, `login_manager`, `csrf`) in a dedicated module to prevent circular import loops.
- **What the tool produced:** Created `extensions.py` in the project root, but also created a duplicate file `app/extensions.py` that re-exported the same objects.
- **What was wrong:** Having two identical extension files created ambiguity about which file was the canonical source of truth and cluttered the codebase.
- **What I did instead:** Deleted `app/extensions.py`, standardized all imports on root `extensions.py`, and added `tests/test_extensions_structure.py` to ensure duplicate files cannot return.

### 5. Missing `FLASK_APP` in Render Deployment Configuration
- **Category:** Deployment & Configuration
- **Date:** 2026-10-23
- **Commit:** [2b4f765](https://github.com/Ramya1113/trustvault/commit/2b4f765)
- **What I asked:** Configure the repository for deployment to Render using `render.yaml` and a build script.
- **What the tool produced:** Initial `render.yaml` and `build.sh` configurations that ran `flask init-db` without setting `FLASK_APP`.
- **What was wrong:** Claude pointed out that Flask only auto-detects `app.py` or `wsgi.py`, so `flask init-db` on Render would fail without `FLASK_APP=run.py`.
- **What I did instead:** Added `export FLASK_APP=run.py` to `build.sh`, added `FLASK_APP=run.py` to `render.yaml`, added `--app run.py` to Flask CLI commands, and added tests in `tests/test_render_config.py`.

### 6. Login Timing Leak for Unknown Usernames
- **Category:** Authorisation & Access Control
- **Date:** 2026-10-23
- **Commit:** [8318d19](https://github.com/Ramya1113/trustvault/commit/8318d19)
- **What I asked:** Handle failed logins for unknown usernames securely without disclosing whether the user exists.
- **What the tool produced:** Returned a generic "Invalid username or password" message, but skipped password verification entirely when `user is None`.
- **What was wrong:** Claude pointed out that unknown usernames skip the password hash, so response time (~1ms vs ~50ms) reveals which usernames exist.
- **What I did instead:** Added a constant dummy password hash (`_DUMMY_PASSWORD_HASH`) and executed `check_password_hash(_DUMMY_PASSWORD_HASH, password)` when `user is None` so execution latency is identical across valid and invalid usernames. Verified in `tests/test_auth_unknown_login.py`.

### 7. Missing Magic-Byte Validation for DOCX and XLSX Uploads
- **Category:** Access Control & Content Validation
- **Date:** 2026-10-23
- **Commit:** [8318d19](https://github.com/Ramya1113/trustvault/commit/8318d19)
- **What I asked:** Enforce magic-byte validation on file uploads to stop attackers from renaming executables or scripts to allowed document extensions.
- **What the tool produced:** Magic-byte validation for PDF, PNG, and JPG, but allowed DOCX and XLSX with only extension string checks.
- **What was wrong:** Claude pointed out that docx and xlsx only had extension checks and no content checks, allowing disguised executables to bypass checks.
- **What I did instead:** Added magic-byte verification for the standard ZIP/OpenXML signature `PK\x03\x04` for DOCX and XLSX files, documented that `.txt` files contain raw arbitrary plaintext and cannot be signature-checked, and verified in `tests/test_magic_bytes_upload.py`.

### 8. Verification of the Per-Organization Audit Lock
- **Category:** Audit Trail
- **Date:** 2026-10-23
- **Commit:** [8318d19](https://github.com/Ramya1113/trustvault/commit/8318d19)
- **What I asked:** Ensure audit logging is concurrency-safe under multi-threaded load so simultaneous requests do not corrupt the cryptographic hash chain.
- **What the tool produced:** The first version of `log_event` had no locking at all, allowing concurrent requests to read the same previous hash.
- **What was wrong:** Claude pointed out that `log_event` reads the previous hash and then inserts, so two concurrent requests can both read the same previous hash. I then had the lock temporarily removed, and the concurrency test failed with only 28 of 30 entries, and passed after the lock was restored.
- **What I did instead:** Restored `with _get_org_lock(actor.org_id):` in `app/audit.py`, pinned Gunicorn to `--workers 1 --threads 4`, and verified that `tests/test_audit_concurrency.py` passes with all 30 entries cleanly chained.

### 9. Spoofable Chain Verification Banner
- **Category:** Audit Trail
- **Date:** 2026-10-24
- **Commit:** [1e4cd71](https://github.com/Ramya1113/trustvault/commit/1e4cd71)
- **What I asked:** Display a clear verification banner on the audit log page after an administrator triggers chain verification.
- **What the tool produced:** The verify route executed `verify_chain()` and redirected to `/admin/audit?verified=1&valid=1`, with the template displaying the success banner based on query parameters.
- **What was wrong:** The chain verification banner was spoofable; visiting `/admin/audit?verified=1&valid=1` directly in the browser showed "Chain Verification Passed: All entries intact" without running any cryptographic verification.
- **What I did instead:** Removed URL query parameter trust completely; updated `/admin/audit/verify` to store the verified result in server-side session via `session.pop()`, ensured only one banner renders, and added `test_audit_verify_banner_not_spoofable_via_query_params` in `tests/test_admin.py` to confirm query parameters cannot trigger the banner.

---

## How I Used Two AIs

Antigravity generated the code from my step-by-step prompts, and Claude was used to plan the prompts and review Antigravity's summaries for security and deployment problems. I read the results and ran the live checks listed below.

---

## What I Verified Myself

1. **Local App Testing:** Personally tested the local application running on `http://127.0.0.1:5000` as viewer, owner, and admin.
2. **Audit Tamper Detection:** The automated test modifies an audit row directly in the database and `verify_chain` detects it (I did not edit the database by hand).
3. **Automated Test Suite:** Ran the automated pytest integration and unit test suite, achieving a 100% pass rate.

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
