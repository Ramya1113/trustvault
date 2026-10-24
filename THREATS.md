# TrustVault Threat Model & Defensive Mitigations

This document details the security threats evaluated in TrustVault, the exact server-side defences implemented in the codebase, and the automated test proof for each defence.

Every defence listed below is implemented in the application code and verified by a passing automated test.

---

## Threat Defences

### 1. Deactivated User Session Hijacking and Persistence
- **The Attack**: An administrator deactivates a compromised or offboarded user account, but the user continues to execute actions and access confidential documents using a pre-existing, active session cookie.
- **The Defence**: Two-tier session invalidation:
  1. [`load_user()`](file:///d:/trustvault/app/__init__.py#L58-L69) checks `user.is_active` on every request and returns `None` if the user is deactivated, immediately invalidating the Flask-Login session.
  2. [`enforce_active_session()`](file:///d:/trustvault/app/__init__.py#L71-L77) runs as an `@app.before_request` hook, explicitly calling `logout_user()` and redirecting to the login page if an authenticated session belongs to a deactivated user.
- **File and Function**: [`app/__init__.py`](file:///d:/trustvault/app/__init__.py) (`load_user`, `enforce_active_session`)
- **Exact Test Name**: `test_deactivated_user_session_stops_on_next_request` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_deactivated_user_session_invalidated_immediately` (in [`tests/test_access_invalidation.py`](file:///d:/trustvault/tests/test_access_invalidation.py))

---

### 2. Unauthorized Access to Soft-Deleted Documents
- **The Attack**: An attacker attempts to view, download, edit, delete, or manage sharing permissions for previously deleted documents by guessing or supplying their numeric IDs.
- **The Defence**: All document lookups across both [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) and [`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py) filter by `deleted_at=None`. If `deleted_at` is set, the application returns HTTP 404 Not Found before processing any action.
- **File and Function**: [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) (`_get_document_or_abort`) and [`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py) (`_get_document_for_manage_access`)
- **Exact Test Name**: `test_soft_deleted_document_returns_404_on_all_endpoints` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py))

---

### 3. Privilege Escalation via Registration and User Form Tampering
- **The Attack**: An attacker attempts mass-assignment or field injection by adding extra form parameters (such as `role=admin` or `org_id=1`) during self-registration or user creation to acquire administrative rights or infiltrate another organization.
- **The Defence**:
  1. [`register()`](file:///d:/trustvault/app/blueprints/auth.py) ignores injected fields, hardcodes `role='owner'`, and creates a new `Organization`.
  2. [`create_user()`](file:///d:/trustvault/app/blueprints/admin.py) strictly binds new user accounts to `org_id=current_user.org_id`.
  3. Strict WTForms definitions only accept defined schema fields.
- **File and Function**: [`app/blueprints/auth.py`](file:///d:/trustvault/app/blueprints/auth.py) (`register`) and [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`create_user`)
- **Exact Test Name**: `test_user_cannot_set_role_or_org_id_via_form_fields` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_register_ignores_spoofed_role_and_org_id_fields` (in [`tests/test_form_tampering_and_enumeration.py`](file:///d:/trustvault/tests/test_form_tampering_and_enumeration.py))

---

### 4. Open Redirect Phishing via Login `next` Parameter
- **The Attack**: An attacker distributes malicious links with crafted `?next=` query parameters (e.g. `https://evil.com`, `//evil.com`, `javascript:...`) to redirect authenticated users to an external phishing portal after successful login.
- **The Defence**: [`is_safe_redirect_url()`](file:///d:/trustvault/app/blueprints/auth.py) inspects the target redirect path using `urllib.parse.urlsplit`. It rejects any URL with an external host, scheme, leading double slashes (`//`), backslashes, or control characters, falling back to [`documents.list_documents`](file:///d:/trustvault/app/blueprints/documents.py).
- **File and Function**: [`app/blueprints/auth.py`](file:///d:/trustvault/app/blueprints/auth.py) (`is_safe_redirect_url`, `login`)
- **Exact Test Name**: `test_login_next_parameter_cannot_redirect_externally` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_external_url_redirects_to_documents_index` (in [`tests/test_login_redirect.py`](file:///d:/trustvault/tests/test_login_redirect.py))

---

### 5. Stored Cross-Site Scripting (XSS) via Filenames and Metadata
- **The Attack**: An attacker injects JavaScript payloads into document titles, descriptions, or filenames (e.g. `<script>alert(1)</script>`) to execute arbitrary client script in the browser of other users or administrators viewing list, detail, or audit log pages.
- **The Defence**: Jinja2 auto-escaping is active across all application templates, converting characters like `<`, `>`, `&`, and `"` into HTML entities (`&lt;script&gt;`). Additionally, a strict Content Security Policy (`default-src 'self'`) prevents execution of inline scripts and untrusted resources.
- **File and Function**: [`app/templates/documents/list.html`](file:///d:/trustvault/app/templates/documents/list.html), [`app/templates/documents/detail.html`](file:///d:/trustvault/app/templates/documents/detail.html), [`app/templates/admin/audit.html`](file:///d:/trustvault/app/templates/admin/audit.html), and [`app/__init__.py`](file:///d:/trustvault/app/__init__.py) (`add_security_headers`)
- **Exact Test Name**: `test_xss_escaping_on_list_detail_and_audit_pages` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py))

---

### 6. HTTP Response Header Splitting & CRLF Injection in File Downloads
- **The Attack**: An attacker uploads a file with a name containing carriage returns, newlines (`\r\n`), or unescaped quotes to inject rogue HTTP headers (e.g. `Set-Cookie: evil=1`) or escape the `Content-Disposition` attachment filename parameter.
- **The Defence**: In [`download()`](file:///d:/trustvault/app/blueprints/documents.py), filenames are sanitized via `secure_filename()` and stripped of all `\r`, `\n`, and `"` characters before being formatted into `attachment; filename="<clean_filename>"`.
- **File and Function**: [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) (`download`)
- **Exact Test Name**: `test_filename_quotes_and_newlines_cannot_inject_headers` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_filename_crlf_header_injection_prevented` (in [`tests/test_download_header_safety.py`](file:///d:/trustvault/tests/test_download_header_safety.py))

---

### 7. Cross-Tenant Sharing and Access Grants to Inactive Accounts
- **The Attack**: An owner attempts to grant document access to a user in a different organization (cross-tenant leakage) or to a deactivated colleague.
- **The Defence**: [`grant_access()`](file:///d:/trustvault/app/blueprints/sharing.py) verifies that the target user's `org_id` strictly matches `current_user.org_id` and that `target_user.is_active` is True. Violations abort with a flash error and record a `denied` audit entry.
- **File and Function**: [`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py) (`grant_access`)
- **Exact Test Name**: `test_owner_cannot_grant_access_to_cross_org_or_deactivated_user` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_cannot_grant_access_to_cross_tenant_user` (in [`tests/test_sharing.py`](file:///d:/trustvault/tests/test_sharing.py))

---

### 8. Stale Permissions Following Access Revocation
- **The Attack**: A viewer who was granted edit access to a document continues editing after the owner revokes the permission.
- **The Defence**: [`can()`](file:///d:/trustvault/app/permissions.py) and [`require()`](file:///d:/trustvault/app/permissions.py) evaluate the database on every request, verifying `revoked_at is None`. Revoking a grant takes effect immediately on the very next request, returning HTTP 403 Forbidden.
- **File and Function**: [`app/permissions.py`](file:///d:/trustvault/app/permissions.py) (`can`, `require`) and [`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py) (`revoke_access`)
- **Exact Test Name**: `test_revoked_edit_grant_viewer_cannot_edit_on_next_request` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_revoked_grant_stops_edit_immediately` (in [`tests/test_access_invalidation.py`](file:///d:/trustvault/tests/test_access_invalidation.py))

---

### 9. Cross-Tenant Admin Data Snooping and Modification
- **The Attack**: An administrator of Tenant A attempts to view, toggle, or modify user accounts, documents, or audit logs belonging to Tenant B.
- **The Defence**: All queries in [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) strictly enforce `filter_by(org_id=current_user.org_id)`. Inter-tenant lookups return HTTP 404 and record a `denied` audit event.
- **File and Function**: [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`audit_log`, `users_list`, `documents_list`, `toggle_user_status`, `change_user_role`)
- **Exact Test Name**: `test_cross_tenant_admin_isolation_documents_users_audit` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_admin_cannot_see_other_org_users` (in [`tests/test_admin.py`](file:///d:/trustvault/tests/test_admin.py))

---

### 10. State Modification via HTTP GET / Cross-Site Request Forgery (CSRF)
- **The Attack**: An attacker triggers state changes (logout, document deletion, permission grants/revocations, user creation, user role changes, user deactivations, audit chain verification) via GET requests, link prefetching, or image tags.
- **The Defence**: All state-changing routes strictly specify `methods=['POST']`, returning HTTP 405 Method Not Allowed when targeted with GET requests. Every POST request is protected by Flask-WTF CSRF tokens (`csrf.protect`).
- **File and Function**:
  - [`app/blueprints/auth.py`](file:///d:/trustvault/app/blueprints/auth.py) (`logout`)
  - [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) (`delete`)
  - [`app/blueprints/sharing.py`](file:///d:/trustvault/app/blueprints/sharing.py) (`grant_access`, `change_permission`, `revoke_access`)
  - [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`create_user`, `toggle_user_status`, `change_user_role`, `verify_audit_chain`)
- **Exact Test Name**: `test_every_state_changing_route_rejects_get` (in [`tests/test_threat_defences.py`](file:///d:/trustvault/tests/test_threat_defences.py)) and `test_logout_post_with_csrf_succeeds` (in [`tests/test_state_changing_csrf.py`](file:///d:/trustvault/tests/test_state_changing_csrf.py))

---

### 11. Silent Audit Trail Tampering and Modification
- **The Attack**: An unauthorized insider or attacker updates or deletes audit trail rows to cover unauthorized access.
- **The Defence**:
  1. SHA-256 cryptographic hash chaining (`prev_hash` + fields -> `entry_hash`) links every record to its predecessor.
  2. SQLAlchemy ORM listeners block `before_update` and `before_delete` on `AuditLog`.
  3. [`verify_chain()`](file:///d:/trustvault/app/audit.py) recalculates hashes and flags any tampered or deleted entry.
- **File and Function**: [`app/audit.py`](file:///d:/trustvault/app/audit.py) (`log_event`, `verify_chain`) and [`app/models.py`](file:///d:/trustvault/app/models.py) (`prevent_audit_log_modification`)
- **Exact Test Name**: `test_tampered_row_in_db_fails_verify_chain` (in [`tests/test_audit.py`](file:///d:/trustvault/tests/test_audit.py)) and `test_audit_log_append_only_enforced_by_orm` (in [`tests/test_audit.py`](file:///d:/trustvault/tests/test_audit.py))

---

### 12. Verification Banner Spoofing via URL Parameters
- **The Attack**: An attacker tricks an administrator into believing the audit chain passed verification by appending spoofed query parameters like `?verified=1&valid=1` to the URL.
- **The Defence**: Chain verification runs exclusively via server-side POST ([`verify_audit_chain()`](file:///d:/trustvault/app/blueprints/admin.py)). The result is saved in the server-managed session (`session['verification_status']`) and popped on display. Query parameters in the URL are ignored.
- **File and Function**: [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`audit_log`, `verify_audit_chain`)
- **Exact Test Name**: `test_audit_page_ignores_spoofed_url_query_parameters` (in [`tests/test_admin.py`](file:///d:/trustvault/tests/test_admin.py)) and `test_audit_verify_post_sets_session_and_renders_banner` (in [`tests/test_admin.py`](file:///d:/trustvault/tests/test_admin.py))

---

### 13. File Signature Spoofing and Executable Disguise
- **The Attack**: An attacker uploads executable binaries or web shells disguised with an allowed file extension (e.g. `.exe` renamed to `.pdf` or `.docx`).
- **The Defence**: [`_validate_magic_bytes()`](file:///d:/trustvault/app/blueprints/documents.py) inspects the initial byte sequences against authoritative signatures: `%PDF-` for PDF, `\x89PNG\r\n\x1a\n` for PNG, `\xff\xd8\xff` for JPG/JPEG, and `PK\x03\x04` for DOCX/XLSX.
- **File and Function**: [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) (`_validate_magic_bytes`, `upload`)
- **Exact Test Name**: `test_magic_bytes_spoofing_rejected` (in [`tests/test_magic_bytes_upload.py`](file:///d:/trustvault/tests/test_magic_bytes_upload.py)) and `test_magic_bytes_spoofed_docx_and_xlsx_rejected` (in [`tests/test_magic_bytes_upload.py`](file:///d:/trustvault/tests/test_magic_bytes_upload.py))

---

### 14. Timing-Attack Account Enumeration and Credential Brute-Forcing
- **The Attack**: An attacker measures response latency to determine whether a username exists (timing leak) or conducts rapid brute-force password guessing.
- **The Defence**:
  1. For non-existent usernames, [`login()`](file:///d:/trustvault/app/blueprints/auth.py) executes a dummy password hash check (`_DUMMY_PASSWORD_HASH`) to equalize server response timing with valid users.
  2. The in-memory lockout tracker locks authentication for 10 minutes after 5 consecutive failed attempts, returning HTTP 429 Too Many Requests.
- **File and Function**: [`app/blueprints/auth.py`](file:///d:/trustvault/app/blueprints/auth.py) (`login`, `_record_failed_attempt`, `_is_locked_out`)
- **Exact Test Name**: `test_unknown_username_runs_dummy_password_hash_check` (in [`tests/test_auth_unknown_login.py`](file:///d:/trustvault/tests/test_auth_unknown_login.py)) and `test_rate_limit_lockout_after_five_failed_logins` (in [`tests/test_auth.py`](file:///d:/trustvault/tests/test_auth.py))

---

### 15. Clickjacking and MIME Confusion Attacks
- **The Attack**: An attacker embeds TrustVault in a transparent iframe to steal user interactions (clickjacking) or relies on browsers sniffing file types to execute script in place of images/documents.
- **The Defence**: Global response headers injected via [`add_security_headers()`](file:///d:/trustvault/app/__init__.py):
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Content-Security-Policy: default-src 'self'`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **File and Function**: [`app/__init__.py`](file:///d:/trustvault/app/__init__.py) (`add_security_headers`)
- **Exact Test Name**: `test_security_headers_present_on_all_responses` (in [`tests/test_security_headers.py`](file:///d:/trustvault/tests/test_security_headers.py))

---

### 16. Accidental Administrative Demotion or Deactivation
- **The Attack**: An administrator inadvertently deactivates or demotes the sole active administrator in an organization, leaving the tenant permanently orphaned.
- **The Defence**: Both [`toggle_user_status()`](file:///d:/trustvault/app/blueprints/admin.py) and [`change_user_role()`](file:///d:/trustvault/app/blueprints/admin.py) verify that `active_admin_count > 1` before allowing deactivation or demotion of an active administrator.
- **File and Function**: [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`toggle_user_status`, `change_user_role`)
- **Exact Test Name**: `test_admin_cannot_deactivate_last_active_admin` (in [`tests/test_admin.py`](file:///d:/trustvault/tests/test_admin.py)) and `test_admin_cannot_demote_last_active_admin` (in [`tests/test_admin.py`](file:///d:/trustvault/tests/test_admin.py))

---

### 17. Memory Exhaustion via Large Payload BLOB Queries
- **The Attack**: Querying rosters or lists containing many documents loads large binary payloads into server RAM, causing Out-Of-Memory (OOM) application denial of service.
- **The Defence**: List queries in [`list_documents()`](file:///d:/trustvault/app/blueprints/documents.py) and [`documents_list()`](file:///d:/trustvault/app/blueprints/admin.py) apply SQLAlchemy `defer(Document.data)`. Document data BLOBs are only retrieved when serving explicit single-file downloads.
- **File and Function**: [`app/blueprints/documents.py`](file:///d:/trustvault/app/blueprints/documents.py) (`list_documents`) and [`app/blueprints/admin.py`](file:///d:/trustvault/app/blueprints/admin.py) (`documents_list`)
- **Exact Test Name**: `test_documents_list_query_defers_data` (in [`tests/test_document_defer.py`](file:///d:/trustvault/tests/test_document_defer.py)) and `test_admin_documents_list_defers_data` (in [`tests/test_document_defer.py`](file:///d:/trustvault/tests/test_document_defer.py))

---

## What I did not defend against

The following items are known limitations and architectural boundaries where no active defence or automated test exists in the codebase:

1. **In-Memory Lockout Resets on Server Restart**: The failed login lockout tracker (`_LOGIN_ATTEMPTS`) is stored in Python process memory. Restarting or redeploying the web server resets the lockout counter, allowing an attacker to resume password attempts immediately.
2. **One-Worker Lock Scope for Audit Trail**: The audit lock (`_get_org_lock`) uses an in-memory `threading.Lock`. While Gunicorn is pinned to 1 worker process in production (`--workers 1 --threads 4`), any multi-worker or multi-container deployment would require database-level locking (`SELECT ... FOR UPDATE` or advisory locks) or an external sequencer to prevent race conditions across separate OS processes.
3. **Full Audit Chain Regeneration by a DBA**: An attacker with direct database write credentials (e.g. root PostgreSQL/SQLite access) can alter past audit rows and recalculate all downstream SHA-256 hashes. TrustVault does not publish external cryptographic checkpoints (such as external write-once storage, public ledger anchoring, or digital timestamping).
4. **No Email Verification**: Account registration does not send verification emails or confirm mailbox ownership. Users can register organizations using arbitrary or unverified email addresses.
5. **No Multi-Factor Authentication (MFA / 2FA)**: User authentication relies solely on a single factor (username and password). Stolen or compromised credentials grant full access to that user's role.
6. **No Antivirus / Malware Scanning**: Uploaded documents are checked for allowed extensions and binary magic numbers, but file contents are not scanned for malicious macros, embedded exploits, or zero-day malware via ClamAV or a sandboxed scanning engine.
7. **Plaintext Files Accepted Without Signature Verification**: Plain text files (`.txt`) have no standardized magic bytes and are accepted solely based on extension without content inspection.
8. **No Self-Service Password Reset or Account Recovery**: The application lacks password recovery mechanisms (e.g. reset tokens or email recovery links). Account recovery must be performed manually by an organization administrator.
9. **Client-Side Cookie Session Storage**: Flask sessions are stored in client-side signed cookies (`SECRET_KEY`) rather than server-side session stores (such as Redis). While sessions are tamper-proof and invalidated upon deactivation, individual session IDs cannot be selectively revoked server-side while keeping the user active.
