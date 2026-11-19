# Database Architecture — VAJRAKAVACH 2070

**Engine:** SQLite 3 (MVP / Termux / Single-Node) — standard ANSI SQL schema portable to PostgreSQL 16+ for Enterprise scale.

## Core Tables

1. `tenants` — `id`, `name`, `sector` (`government`, `banking`, `enterprise`, `research`), `created_at`
2. `users` — `id`, `tenant_id`, `email`, `full_name`, `role`, `password_salt`, `password_hash`, `mfa_secret`, `mfa_enabled`, `is_active`, `created_at`
3. `assets` — `id`, `tenant_id`, `name`, `asset_type`, `owner`, `environment`, `criticality`, `ip_or_uri`, `nist_function`, `status`, `created_at`
4. `risks` — `id`, `tenant_id`, `asset_id`, `title`, `description`, `likelihood` (1–5), `impact` (1–5), `risk_score` (1–25), `severity`, `status`, `mitigation_plan`, `created_at`
5. `security_events` — `id`, `tenant_id`, `asset_id`, `source`, `event_type`, `severity`, `mitre_tactic`, `summary`, `raw_metadata`, `created_at`
6. `soc_cases` — `id`, `tenant_id`, `title`, `severity`, `status`, `related_event_id`, `assigned_to`, `human_approved_by`, `human_approved_at`, `analyst_notes`, `created_at`
7. `evidence_items` — `id`, `tenant_id`, `case_id`, `title`, `source`, `acquisition_method`, `collector_user_id`, `content_payload`, `sha256_hash`, `sha512_hash`, `created_at`
8. `evidence_custody_events` — `id`, `tenant_id`, `evidence_id`, `actor_user_id`, `action`, `notes`, `created_at`
9. `tool_registry` — `id`, `tenant_id`, `name`, `category`, `vendor`, `official_source`, `license`, `version`, `platform`, `risk_level`, `sandbox_required`, `approval_status`, `notes`, `updated_at`
10. `compliance_controls` — `id`, `tenant_id`, `framework`, `control_code`, `title`, `status`, `evidence_ref`, `updated_at`
11. `audit_logs` — `id`, `tenant_id`, `actor_user_id`, `actor_email`, `action`, `resource_type`, `resource_id`, `details_json`, `prev_hash`, `entry_hash`, `created_at`
