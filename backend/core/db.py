import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend import config


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target = Path(db_path) if db_path else config.DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sector TEXT NOT NULL DEFAULT 'enterprise',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    owner TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production',
    criticality TEXT NOT NULL DEFAULT 'medium',
    ip_or_uri TEXT DEFAULT '',
    nist_function TEXT NOT NULL DEFAULT 'Identify',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    asset_id INTEGER,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    likelihood INTEGER NOT NULL,
    impact INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    mitigation_plan TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    asset_id INTEGER,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL DEFAULT 'Unmapped',
    summary TEXT NOT NULL,
    raw_metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS soc_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    related_event_id INTEGER,
    assigned_to TEXT NOT NULL DEFAULT 'Unassigned',
    human_approved_by TEXT,
    human_approved_at TEXT,
    analyst_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (related_event_id) REFERENCES security_events(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    case_id INTEGER,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    acquisition_method TEXT NOT NULL,
    collector_user_id INTEGER NOT NULL,
    content_payload TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    sha512_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES soc_cases(id) ON DELETE SET NULL,
    FOREIGN KEY (collector_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS evidence_custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    evidence_id INTEGER NOT NULL,
    actor_user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tool_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    vendor TEXT NOT NULL,
    official_source TEXT NOT NULL,
    license TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    sandbox_required INTEGER NOT NULL DEFAULT 1,
    approval_status TEXT NOT NULL DEFAULT 'research',
    notes TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    framework TEXT NOT NULL,
    control_code TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'in_progress',
    evidence_ref TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    actor_user_id INTEGER,
    actor_email TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    assessment_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    score INTEGER NOT NULL,
    findings_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    risk_tier TEXT NOT NULL DEFAULT 'medium',
    rag_enabled INTEGER NOT NULL DEFAULT 0,
    human_approval_required INTEGER NOT NULL DEFAULT 1,
    allowed_tools TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    model_name TEXT NOT NULL,
    prompt_injection_risk TEXT NOT NULL,
    pii_leakage_risk TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    indicator TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL DEFAULT 'Command and Control',
    confidence INTEGER NOT NULL DEFAULT 75,
    source_reliability TEXT NOT NULL DEFAULT 'B',
    source_name TEXT NOT NULL DEFAULT 'manual_intel',
    expires_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sbom_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    total_packages INTEGER NOT NULL,
    unpinned_count INTEGER NOT NULL,
    sbom_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
"""

DEFAULT_VERIFIED_TOOLS = [
    ("Wazuh", "SIEM / XDR", "Wazuh Inc.", "https://wazuh.com", "GPLv2 / Apache 2.0", "4.x", "Linux / Cloud", "medium", 1, "research", "Security event monitoring & log analysis candidate."),
    ("Zeek", "Network Monitoring", "The Zeek Project", "https://zeek.org", "BSD-3-Clause", "6.x", "Linux / BSD", "low", 1, "research", "Passive network metadata analysis."),
    ("Suricata", "Network IDS/IPS", "OISF", "https://suricata.io", "GPLv2", "7.x", "Linux / Windows", "medium", 1, "research", "Network signature and anomaly detection."),
    ("MISP", "Threat Intelligence", "MISP Project", "https://www.misp-project.org", "AGPLv3", "2.4.x", "Linux", "low", 1, "research", "Structured threat indicator sharing."),
    ("Semgrep", "Static Code Analysis", "Semgrep Inc.", "https://semgrep.dev", "LGPL-2.1", "1.x", "Cross-platform", "low", 1, "research", "Defensive secure code review."),
    ("Trivy", "Container & SBOM Security", "Aqua Security", "https://trivy.dev", "Apache 2.0", "0.5x", "Cross-platform", "low", 1, "research", "Container, IaC, and dependency vulnerability scanner."),
    ("Autopsy", "Digital Forensics", "Basis Technology", "https://www.autopsy.com", "Apache 2.0", "4.x", "Linux / Windows / macOS", "low", 1, "research", "Forensic disk & artifact analysis."),
    ("Volatility 3", "Memory Forensics", "Volatility Foundation", "https://volatilityfoundation.org", "VSL", "2.x", "Cross-platform", "low", 1, "research", "RAM image defensive forensic analysis."),
    ("YARA", "Defensive Detection Rules", "VirusTotal / Community", "https://virustotal.github.io/yara/", "BSD-3-Clause", "4.x", "Cross-platform", "low", 1, "research", "Pattern matching for defensive file classification."),
    ("TheHive", "Incident Case Management", "StrangeBee", "https://strangebee.com/thehive/", "Commercial / AGPL Legacy", "5.x", "Linux / Cloud", "medium", 1, "research", "Structured incident response case workflow."),
]

DEFAULT_COMPLIANCE_CONTROLS = [
    ("NIST CSF 2.0", "GV.OC-01", "Organizational cybersecurity governance & authorization policy", "implemented", "RBAC + Tenant Policy Engine"),
    ("NIST CSF 2.0", "ID.AM-01", "Hardware, software, cloud, API & AI asset inventory maintained", "implemented", "Asset Intelligence Module"),
    ("NIST CSF 2.0", "PR.AA-01", "Identity management, MFA & least-privilege RBAC enforced", "implemented", "PBKDF2 + TOTP MFA + RBAC"),
    ("NIST CSF 2.0", "DE.CM-01", "Continuous security event monitoring & alert correlation", "implemented", "Basic SOC Event Ingestion"),
    ("NIST CSF 2.0", "RS.MI-01", "Incident containment with mandatory human approval gate", "implemented", "SOC Case Human Approval"),
    ("NIST CSF 2.0", "RC.RP-01", "Backup verification and disaster recovery readiness", "in_progress", "Phase 2 Backup SOP"),
    ("CERT-In 2022", "CI-6H-01", "6-hour cyber incident reporting readiness workflow", "in_progress", "SOC High/Critical Case Trigger"),
    ("CERT-In 2022", "CI-LOG-02", "Tamper-evident security audit log retention (180+ days)", "implemented", "SHA-256 Hash-Chained Audit Log"),
    ("RBI Directions 2026", "RBI-GOV-01", "IT governance, asset inventory & vulnerability risk register", "implemented", "Assets + Risk Register"),
    ("RBI Directions 2026", "RBI-AUD-02", "Verifiable audit trail & tenant data isolation", "implemented", "Audit Verifier + Tenant Guard"),
    ("MeitY DPDP Rules 2025", "DPDP-MIN-01", "Lawful data boundary & tenant-scoped access minimization", "implemented", "Strict Tenant Isolation"),
    ("OWASP GenAI 2026", "AI-GOV-01", "Human-in-the-loop approval for high-impact actions", "implemented", "Explicit Human Reviewer Logging"),
]


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def seed_tenant_defaults(conn: sqlite3.Connection, tenant_id: int) -> None:
    now = utc_now()
    for tool in DEFAULT_VERIFIED_TOOLS:
        conn.execute(
            """INSERT INTO tool_registry
               (tenant_id, name, category, vendor, official_source, license, version,
                platform, risk_level, sandbox_required, approval_status, notes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, *tool, now),
        )
    for ctrl in DEFAULT_COMPLIANCE_CONTROLS:
        conn.execute(
            """INSERT INTO compliance_controls
               (tenant_id, framework, control_code, title, status, evidence_ref, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, *ctrl, now),
        )
