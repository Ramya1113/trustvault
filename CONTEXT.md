# Project Context: TrustVault

> **Instruction for AI Agents and Developers:**  
> Read this file (`CONTEXT.md`) before every future task to ensure complete alignment with project principles, architecture, security boundaries, and coding standards.

---

## 1. Project Overview
**TrustVault** is a secure, multi-tenant document-sharing platform built with simplicity, safety, and strict tenancy isolation at its core.

### Core Tenancy Rules
- **Strict Multi-Tenancy:** Every user belongs to exactly **one Organization (tenant)**.
- **Zero Cross-Tenant Leakage:** Under no circumstances should data, queries, or access cross tenants. All queries and access checks must be scoped to the user's organization.

---

## 2. User Roles & Capabilities
The system defines three core roles:

1. **Admin:**
   - Manages users within their own organization.
   - Can access and manage all documents belonging to their own organization.
2. **Owner:**
   - Uploads documents to their organization's vault.
   - Grants and revokes read or edit access on documents they uploaded.
3. **Viewer:**
   - Can only open documents that have been explicitly shared with them.
   - Can **never** manage document access or grant permissions to others.

---

## 3. Security & Authorization Architecture
- **Centralized Server-Side Authorization:**
  - **ALL** authorization decisions are enforced on the server in a single, centralized function: `app/permissions.py`.
  - **Never rely on UI obfuscation or hiding buttons** for security. Every API endpoint and view must validate permissions via `app/permissions.py`.
- **Tamper-Evident Audit Logging:**
  - Every sensitive action (document uploads, access grants, revocations, document views, modifications, deletions, authentication events) **must** be recorded.
  - **Crucially: DENIED attempts must also be logged.**
  - The audit log is **append-only** and **hash-chained** (each log entry contains a cryptographic hash of the previous log entry and its own contents) to guarantee tamper-evidence.

---

## 4. Technology Stack & Constraints
- **Language & Core Framework:** Python 3, Flask.
- **ORM & Data Layer:** Flask-SQLAlchemy.
  - **Local Development:** SQLite (defaulting to local database in `instance/` or root).
  - **Production:** PostgreSQL via the `DATABASE_URL` environment variable.
- **Document Storage:**
  - Files are stored directly as **BLOBs in the database**.
  - Maximum file size: **5 MB**.
- **Authentication & Security:**
  - Session Management: Flask-Login.
  - Form & Request Protection: Flask-WTF (CSRF protection enabled across all state-changing endpoints).
- **Testing:** pytest.
- **Dependencies:** Keep dependencies minimal and strictly necessary (no unneeded libraries or heavy dependencies).

---

## 5. Development Principles & Code Style
- **Clarity & Simplicity:** Code must be kept clean, readable, and well-commented so a beginner can easily understand and explain how every component works.
- **Safe Defaults:** Deny access by default; allow access only upon explicit authorization check.
- **No Premature Features:** Build incrementally following instructions, avoiding speculative or unrequested features.
