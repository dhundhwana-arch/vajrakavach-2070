# Security, Privacy & Threat Model — VAJRAKAVACH 2070

**Founder & Developer:** Divyesh Bambhaniya

## 1. STRIDE Threat Model Summary

| Threat | Risk Scenario | Mitigation Implemented in `v0.2.0` |
| :--- | :--- | :--- |
| **Spoofing** | Stolen or weak credentials | Salted PBKDF2-HMAC-SHA256 (120,000 iterations), HMAC-SHA256 signed tokens, optional RFC 6238 TOTP MFA |
| **Tampering** | Altering audit logs or forensic evidence | Append-only SHA-256 hash-chained audit logs + SHA-256/512 evidence digest verification |
| **Repudiation** | Denying who approved a case or tool | Every state-changing action records `actor_user_id`, `actor_email`, timestamp, and chained hash |
| **Information Disclosure** | Cross-tenant data leakage | Strict `tenant_id` enforcement derived solely from signed auth token; automated cross-tenant tests |
| **Denial of Service** | Unbounded request body or abuse | Request payload size caps, structured error handling, stateless token verification |
| **Elevation of Privilege** | Read-only user modifying security controls | Strict RBAC decorator/guard checked before every write endpoint |

## 2. Indian & Global Compliance Alignment (Architecture Guidance, Not Legal Advice)
- **NIST Cybersecurity Framework (CSF) 2.0:** Govern, Identify, Protect, Detect, Respond, Recover mapped directly in `compliance_controls`.
- **CERT-In Directions (2022):** 6-hour cyber incident reporting readiness checklist and log retention controls.
- **RBI Cybersecurity Directions (2026):** Banking asset inventory, secure configuration, audit logging, and incident resilience tracking.
- **MeitY DPDP Act 2023 & DPDP Rules 2025:** Data minimization, tenant-scoped access control, and retention/deletion governance.
- **OWASP ASVS 5.0 / API Top 10 / GenAI Security:** Object-level authorization checks, human-approval gates for high-impact actions.
