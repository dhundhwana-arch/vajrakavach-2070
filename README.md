# 🇮🇳 VAJRAKAVACH 2070 (વજ્રકવચ)
### Global Cybersecurity & Digital Defense Intelligence Ecosystem

- **Founder:** Divyesh Bambhaniya
- **Project Developer:** Divyesh Bambhaniya
- **Product Identity:** Developer by Divyesh Bambhaniya
- **Current Release:** `v0.2.0` — Phase 1–2 Working Core MVP (Modular Monolith)
- **Long-Term Vision:** 2026–2070 Phased Research & Engineering Roadmap

---

## 🎯 Purpose & Legal Boundary

**VAJRAKAVACH 2070** is a **defensive, lawful, and authorization-first** modular cybersecurity ecosystem designed for authorized Government bodies, Banking & Financial Institutions, Enterprises, Technology Companies, and Cybersecurity Research Labs.

> **Strict Ethical & Legal Boundary:** This platform strictly forbids unauthorized access, credential theft, covert surveillance, illegal data acquisition, or unapproved external testing. All operations operate exclusively on customer-authorized data, public/licensed intelligence, or evidence acquired under valid legal authority.

## ✅ What Is Actually Implemented & Running in `v0.2.0` (Honest Scope)

Rather than faking all 20 future divisions with mock screens, this release implements a **real, working, tested Phase 1–2 Core MVP** using a zero-bloat Python 3 standard library + SQLite modular monolith architecture (100% runnable on **Android Termux**, Linux, macOS, Windows, Docker, and Render without C/Rust compiler issues):

1. **Identity, Auth, MFA & RBAC (`backend/core/security.py`, `backend/modules/auth.py`)**
   - PBKDF2-HMAC-SHA256 password hashing with per-user cryptographic salt
   - Signed HMAC-SHA256 Bearer session tokens with expiry
   - Optional RFC 6238 TOTP (6-digit) Multi-Factor Authentication
   - 8 Role-Based Access Control (RBAC) roles (`platform_owner`, `org_admin`, `security_analyst`, `soc_manager`, `investigator`, `auditor`, `researcher`, `executive`)
   - Strict **Multi-Tenant Isolation** enforced on every query
2. **Tamper-Evident Hash-Chained Audit Log (`backend/core/audit.py`)**
   - Append-only SHA-256 chained audit trail (`prev_hash` → `entry_hash`)
   - Live cryptographic verification endpoint (`/api/v1/audit/verify`)
3. **Asset Intelligence & Risk Register (`backend/modules/assets.py`, `backend/modules/risks.py`)**
   - Full CRUD for hardware, servers, cloud assets, endpoints, domains, APIs, and AI models
   - Asset-linked Risk Register with automatic `Likelihood × Impact` risk scoring and remediation tracking
4. **Basic SOC — Events, Alert Correlation & Cases (`backend/modules/soc.py`)**
   - Security event ingestion with MITRE ATT&CK tactic tagging
   - Automatic rule-based alert correlation (critical/high events & repeated auth failures)
   - Incident Case workflow (`open` → `investigating` → `contained` → `resolved`) with explicit **Human Review Approval**
5. **Digital Forensics & Evidence Integrity (`backend/modules/evidence.py`)**
   - Evidence intake with automatic **SHA-256** and **SHA-512** cryptographic digests
   - Immutable original record + Chain-of-Custody event log + live hash verification
6. **Universal Verified Cybersecurity Tool Registry (`backend/modules/tools.py`)**
   - Pre-seeded catalog of 10 real defensive open-source tools (Wazuh, Zeek, Suricata, MISP, Semgrep, Trivy, Autopsy, Volatility 3, YARA, TheHive) with accurate official sources and licenses
   - Approval lifecycle (`research` → `tested` → `approved` → `disabled`) enforcing the rule: **Tool Catalog ≠ Tool Execution**
7. **Compliance & Governance Tracker (`backend/modules/compliance.py`)**
   - Live control readiness tracking across **NIST CSF 2.0**, **CERT-In Directions (6-hour reporting)**, **RBI Cybersecurity Directions 2026**, and **MeitY DPDP Rules 2025**
8. **Global Security Command Center UI (`frontend/`)**
   - Dark-first Enterprise SOC interface with live **Gujarati (ગુજરાતી) / English** language switching connected directly to the live SQLite-backed REST API.

## 🚀 Quickstart (Termux / Linux / macOS / Windows)

```bash
# 1. Start the server (zero external pip packages required!)
python3 -m backend.app

# 2. Open in browser:
# http://127.0.0.1:8080
```

## 🧪 Run Automated Security & Functional Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests verify:
- Tenant Isolation (Tenant A cannot view or modify Tenant B records)
- RBAC enforcement (read-only/unauthorized roles blocked with HTTP 403)
- TOTP MFA generation & verification
- SHA-256/SHA-512 Evidence Integrity & Chain-of-Custody verification
- Tamper-evident Audit Log hash chain integrity & tamper detection
- End-to-end live HTTP REST API CRUD flows

## 📁 Repository Structure

```text
vajrakavach-2070/
├── backend/                  # Modular monolith Python 3 REST API & SQLite engine
├── frontend/                 # Dark-first Bilingual (Gujarati/English) SOC Dashboard
├── docs/                     # Phase 0 Architecture, PRD, OpenAPI, Threat Model, Guides
├── tests/                    # Automated unit, integration & security test suite
├── scripts/                  # Termux setup & safe GitHub push helper scripts
├── .github/workflows/ci.yml  # GitHub Actions CI test workflow
├── Dockerfile                # Container deployment
└── render.yaml               # Free-tier cloud deployment config
```

## 📚 Documentation (`docs/`)

- `docs/00_MASTER_BLUEPRINT.md` — Master Blueprint & 20-Division Functional Map
- `docs/01_PRD.md` — Phase 1–2 Product Requirements Document
- `docs/02_SYSTEM_ARCHITECTURE.md` — Control/Data/Execution Planes & Isolation Model
- `docs/03_DATABASE_ARCHITECTURE.md` — Relational Schema (SQLite / PostgreSQL)
- `docs/04_API_SPECIFICATION.yaml` — OpenAPI 3.0.3 REST API Contract
- `docs/05_SECURITY_PRIVACY_THREAT_MODEL.md` — STRIDE Threat Model & Indian/Global Compliance
- `docs/06_COMPETITOR_RESEARCH_AND_ROADMAP.md` — Competitor Framework & 2026–2070 Roadmap
- `docs/07_TERMUX_AND_GITHUB_GUIDE.md` — Step-by-step Termux & GitHub Push Guide

---
**Founder & Project Developer:** Divyesh Bambhaniya  
**Product Identity:** Developer by Divyesh Bambhaniya
