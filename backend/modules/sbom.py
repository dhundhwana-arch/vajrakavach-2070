import json
import re
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles


def list_sboms(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT * FROM sbom_records WHERE tenant_id = ? ORDER BY id DESC LIMIT 50", (actor["tid"],)).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["sbom"] = json.loads(item.pop("sbom_json"))
        out.append(item)
    return out


def analyze_sbom(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    project_name = (data.get("project_name") or "").strip()
    ecosystem = (data.get("ecosystem") or "python").strip().lower()
    manifest_text = data.get("manifest_text") or ""

    if not project_name or not manifest_text.strip():
        raise ValueError("project_name and manifest_text are required.")

    components: List[Dict[str, Any]] = []
    unpinned_count = 0

    if ecosystem == "npm":
        try:
            pkg = json.loads(manifest_text)
        except json.JSONDecodeError as exc:
            raise ValueError("For npm ecosystem, manifest_text must be valid package.json JSON.") from exc
        deps = {}
        deps.update(pkg.get("dependencies") or {})
        deps.update(pkg.get("devDependencies") or {})
        for name, ver in sorted(deps.items()):
            ver_str = str(ver).strip()
            pinned = not (ver_str.startswith("^") or ver_str.startswith("~") or ver_str in {"*", "latest", ""})
            if not pinned:
                unpinned_count += 1
            components.append({"name": name, "version": ver_str, "pinned": pinned})
    else:
        for raw_line in manifest_text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", line)
            if not m:
                continue
            name, spec = m.group(1), m.group(2).strip()
            pinned = spec.startswith("==") and len(spec) > 2
            if not pinned:
                unpinned_count += 1
            components.append({"name": name, "version": spec or "unpinned", "pinned": pinned})

    sbom_doc = {
        "bomFormat": "CycloneDX-Lite",
        "specVersion": "1.5",
        "project": project_name,
        "ecosystem": ecosystem,
        "components": components,
    }
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO sbom_records
           (tenant_id, project_name, ecosystem, total_packages, unpinned_count, sbom_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], project_name, ecosystem, len(components), unpinned_count, json.dumps(sbom_doc), now),
    )
    sid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "SBOM_ANALYZED", "sbom", sid, {"project": project_name, "packages": len(components), "unpinned": unpinned_count})
    conn.commit()
    return {
        "id": sid,
        "project_name": project_name,
        "ecosystem": ecosystem,
        "total_packages": len(components),
        "unpinned_count": unpinned_count,
        "sbom": sbom_doc,
        "created_at": now,
    }
