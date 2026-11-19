# Product Requirements Document (PRD) — Phase 1–2 Core MVP

**Project:** VAJRAKAVACH 2070 (`v0.2.0`)  
**Founder & Developer:** Divyesh Bambhaniya

## 1. Objective
Deliver a verified, testable, single-command runnable Core MVP that proves the foundational security guarantees of VAJRAKAVACH 2070: multi-tenant isolation, RBAC, tamper-evident audit logging, cryptographic evidence integrity, asset/risk tracking, basic SOC correlation, and a governed cybersecurity tool registry.

## 2. Functional Requirements & Acceptance Criteria

| Module | Requirement | Acceptance Criteria |
| :--- | :--- | :--- |
| **Identity & Auth** | Tenant registration, salted PBKDF2 passwords, signed tokens, optional TOTP MFA | Passwords never stored in plaintext; invalid tokens rejected with HTTP 401; TOTP validates RFC 6238 codes |
| **Tenant Isolation** | Every record scoped by `tenant_id` | Automated security test proves Tenant A receives HTTP 404/403 when requesting Tenant B's IDs |
| **RBAC** | 8 distinct roles with least-privilege checks | `executive` / `auditor` blocked (HTTP 403) from mutating assets, tools, or SOC cases |
| **Asset Intelligence** | Create, list, update assets across 7 asset types | Persisted in SQLite; criticality validated (`critical`/`high`/`medium`/`low`) |
| **Risk Register** | Link risks to assets; compute `likelihood * impact` (1–25) | Score auto-calculated server-side; severity band derived deterministically |
| **SOC & Cases** | Ingest events; auto-correlate alerts; manage cases with human approval | Critical/high events auto-create correlated alerts; closing/approving case logs human reviewer |
| **Forensic Evidence** | Intake evidence with automatic SHA-256 & SHA-512 hash + Chain of Custody | Live `/verify` recalculates hash and flags any tampering immediately |
| **Tool Registry** | Catalog verified defensive tools; manage approval status | Only `platform_owner` or `org_admin` can approve/disable tools; catalog does not execute tools |
| **Audit Log** | Append-only SHA-256 hash chain for every state change | `/api/v1/audit/verify` detects any altered row in the audit table |
