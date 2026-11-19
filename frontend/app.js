const I18N = {
  gu: {
    subtitle: "વૈશ્વિક સાયબર સુરક્ષા અને ડિજિટલ સંરક્ષણ ઇકોસિસ્ટમ",
    logout: "લોગઆઉટ",
    loginTitle: "🔐 લોગિન (સંસ્થા પોર્ટલ)",
    loginDesc: "તમારા સુરક્ષિત અને અલગ (isolated) ઓર્ગેનાઇઝેશન એકાઉન્ટથી પ્રવેશ કરો.",
    loginBtn: "લોગિન કરો",
    registerTitle: "🏢 નવું ઓર્ગેનાઇઝેશન (Tenant) રજીસ્ટર કરો",
    registerDesc: "PBKDF2 સુરક્ષા, Tool Catalog અને NIST/CERT-In/RBI/DPDP કંટ્રોલ્સ સાથે અલગ Tenant બનાવે છે.",
    registerBtn: "નવું Tenant બનાવો",
    tabOverview: "કમાન્ડ સેન્ટર",
    tabAssets: "એસેટ્સ",
    tabRisks: "રિસ્ક રજીસ્ટર",
    tabSoc: "SOC અને કેસ",
    tabEvidence: "ડિજિટલ ફોરેન્સિક્સ",
    tabTools: "ટૂલ રજીસ્ટ્રી",
    tabCompliance: "કોમ્પ્લાયન્સ અને ઓડિટ",
    auditBannerTitle: "🔒 ક્રિપ્ટોગ્રાફિક ઓડિટ ચેઇન અને કાયદેસર મર્યાદા",
  },
  en: {
    subtitle: "Global Cybersecurity & Digital Defense Intelligence Ecosystem",
    logout: "Logout",
    loginTitle: "🔐 Sign In (Tenant Portal)",
    loginDesc: "Authenticate with your isolated organization account.",
    loginBtn: "Sign In",
    registerTitle: "🏢 Register New Organization Tenant",
    registerDesc: "Creates an isolated tenant with PBKDF2 auth, verified tool catalog, and NIST/CERT-In/RBI/DPDP controls.",
    registerBtn: "Create Isolated Tenant",
    tabOverview: "Command Center",
    tabAssets: "Assets",
    tabRisks: "Risk Register",
    tabSoc: "SOC & Cases",
    tabEvidence: "Digital Forensics",
    tabTools: "Tool Registry",
    tabCompliance: "Compliance & Audit",
    auditBannerTitle: "🔒 Cryptographic Audit Chain & Legal Boundary",
  },
};

let currentLang = "gu";
let token = localStorage.getItem("vajra_token") || "";
let currentUser = JSON.parse(localStorage.getItem("vajra_user") || "null");

function applyLanguage() {
  const dict = I18N[currentLang];
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (dict[key]) el.textContent = dict[key];
  });
}

function showToast(msg, isError = false) {
  const t = document.getElementById("statusToast");
  t.textContent = msg;
  t.className = isError ? "toast error" : "toast";
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 4500);
}

async function api(path, method = "GET", body = null) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function esc(val) {
  return String(val ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function setSession(newToken, user) {
  token = newToken;
  currentUser = user;
  localStorage.setItem("vajra_token", token);
  localStorage.setItem("vajra_user", JSON.stringify(user));
  renderAppState();
}

function clearSession() {
  token = "";
  currentUser = null;
  localStorage.removeItem("vajra_token");
  localStorage.removeItem("vajra_user");
  renderAppState();
}

async function loadAllData() {
  try {
    const [summary, assetsRes, risksRes, casesRes, evRes, toolsRes, compRes, auditRes] = await Promise.all([
      api("/api/v1/dashboard/summary"),
      api("/api/v1/assets"),
      api("/api/v1/risks"),
      api("/api/v1/soc/cases"),
      api("/api/v1/evidence"),
      api("/api/v1/tools"),
      api("/api/v1/compliance"),
      api("/api/v1/audit"),
    ]);

    document.getElementById("kpiGrid").innerHTML = [
      ["Assets", summary.assets_total],
      ["Open Risks", summary.risks_open],
      ["High/Critical Risks", summary.risks_high_critical],
      ["SOC Events", summary.events_total],
      ["Open Cases", summary.cases_open],
      ["Sealed Evidence", summary.evidence_sealed],
      ["Tools (Approved/Total)", `${summary.tools_approved}/${summary.tools_cataloged}`],
      ["Compliance Ready", `${summary.compliance_implemented}/${summary.compliance_total}`],
    ].map(([label, val]) => `<div class="kpi"><div class="label">${esc(label)}</div><div class="val">${esc(val)}</div></div>`).join("");

    const ac = summary.audit_chain;
    document.getElementById("auditStatusText").textContent = ac.valid
      ? `✅ SHA-256 Audit Chain VERIFIED (${ac.checked_entries} entries intact | Latest Hash: ${ac.latest_hash.slice(0, 18)}...)`
      : `❌ ALERT: Audit chain tampered at entry #${ac.broken_at_id}!`;

    document.getElementById("assetsTable").innerHTML =
      "<tr><th>ID</th><th>Name</th><th>Type</th><th>Criticality</th><th>URI/IP</th></tr>" +
      assetsRes.items.map((a) => `<tr><td>${a.id}</td><td>${esc(a.name)}</td><td>${esc(a.asset_type)}</td><td><span class="pill pill-${esc(a.criticality)}">${esc(a.criticality)}</span></td><td>${esc(a.ip_or_uri)}</td></tr>`).join("");

    document.getElementById("risksTable").innerHTML =
      "<tr><th>ID</th><th>Title</th><th>Score</th><th>Severity</th><th>Mitigation</th></tr>" +
      risksRes.items.map((r) => `<tr><td>${r.id}</td><td>${esc(r.title)}</td><td>${r.risk_score}/25</td><td><span class="pill pill-${esc(r.severity)}">${esc(r.severity)}</span></td><td>${esc(r.mitigation_plan)}</td></tr>`).join("");

    document.getElementById("casesTable").innerHTML =
      "<tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Human Reviewer</th><th>Action</th></tr>" +
      casesRes.items.map((c) => `<tr><td>${c.id}</td><td>${esc(c.title)}</td><td><span class="pill pill-${esc(c.severity)}">${esc(c.severity)}</span></td><td><span class="pill pill-${esc(c.status)}">${esc(c.status)}</span></td><td>${esc(c.human_approved_by || "Pending")}</td><td><button class="btn btn-accent btn-sm" onclick="approveCase(${c.id})">Approve &amp; Resolve</button></td></tr>`).join("");

    document.getElementById("evidenceTable").innerHTML =
      "<tr><th>ID</th><th>Title</th><th>Source</th><th>SHA-256</th><th>Verify</th></tr>" +
      evRes.items.map((e) => `<tr><td>${e.id}</td><td>${esc(e.title)}</td><td>${esc(e.source)}</td><td><code>${esc(e.sha256_hash.slice(0, 16))}...</code></td><td><button class="btn btn-primary btn-sm" onclick="verifyEvidence(${e.id})">Verify Hash</button></td></tr>`).join("");

    document.getElementById("toolsTable").innerHTML =
      "<tr><th>Tool</th><th>Category</th><th>License</th><th>Status</th><th>Governance</th></tr>" +
      toolsRes.items.map((t) => `<tr><td><a href="${esc(t.official_source)}" target="_blank" rel="noopener" style="color:#38bdf8">${esc(t.name)}</a></td><td>${esc(t.category)}</td><td>${esc(t.license)}</td><td><span class="pill pill-${esc(t.approval_status)}">${esc(t.approval_status)}</span></td><td><button class="btn btn-outline btn-sm" onclick="setToolStatus(${t.id}, '${t.approval_status === "approved" ? "disabled" : "approved"}')">${t.approval_status === "approved" ? "Disable" : "Approve"}</button></td></tr>`).join("");

    document.getElementById("complianceTable").innerHTML =
      "<tr><th>Framework</th><th>Code</th><th>Control</th><th>Status</th><th>Evidence</th></tr>" +
      compRes.items.map((c) => `<tr><td>${esc(c.framework)}</td><td><code>${esc(c.control_code)}</code></td><td>${esc(c.title)}</td><td><span class="pill pill-${esc(c.status)}">${esc(c.status)}</span></td><td>${esc(c.evidence_ref)}</td></tr>`).join("");

    document.getElementById("auditTable").innerHTML =
      "<tr><th>ID</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Resource</th><th>Entry Hash</th></tr>" +
      auditRes.items.slice(0, 30).map((l) => `<tr><td>${l.id}</td><td>${esc(l.created_at)}</td><td>${esc(l.actor_email)}</td><td>${esc(l.action)}</td><td>${esc(l.resource_type)}#${esc(l.resource_id)}</td><td><code>${esc(l.entry_hash.slice(0, 14))}...</code></td></tr>`).join("");
  } catch (err) {
    showToast(err.message, true);
    if (err.message.toLowerCase().includes("token") || err.message.toLowerCase().includes("expired")) {
      clearSession();
    }
  }
}

window.approveCase = async function (caseId) {
  try {
    await api(`/api/v1/soc/cases/${caseId}`, "PATCH", { status: "resolved", analyst_notes: "Verified & resolved by human reviewer." });
    showToast(`Case #${caseId} approved & resolved.`);
    loadAllData();
  } catch (err) { showToast(err.message, true); }
};

window.verifyEvidence = async function (evidenceId) {
  try {
    const res = await api(`/api/v1/evidence/${evidenceId}/verify`);
    const box = document.getElementById("evidenceVerifyBox");
    box.textContent = JSON.stringify(res, null, 2);
    box.classList.remove("hidden");
    showToast(res.intact ? `Evidence #${evidenceId} SHA-256 intact!` : `WARNING: Evidence #${evidenceId} tampered!`, !res.intact);
  } catch (err) { showToast(err.message, true); }
};

window.setToolStatus = async function (toolId, nextStatus) {
  try {
    await api(`/api/v1/tools/${toolId}/status`, "PATCH", { approval_status: nextStatus });
    showToast(`Tool #${toolId} status updated to ${nextStatus}.`);
    loadAllData();
  } catch (err) { showToast(err.message, true); }
};

function renderAppState() {
  const loggedIn = Boolean(token && currentUser);
  document.getElementById("authSection").classList.toggle("hidden", loggedIn);
  document.getElementById("workspaceSection").classList.toggle("hidden", !loggedIn);
  document.getElementById("logoutBtn").classList.toggle("hidden", !loggedIn);
  const chip = document.getElementById("userChip");
  chip.classList.toggle("hidden", !loggedIn);
  if (loggedIn) {
    chip.textContent = `${currentUser.tenant_name || "Tenant"} | ${currentUser.email} (${currentUser.role})`;
    loadAllData();
  }
}

document.getElementById("langToggle").addEventListener("click", () => {
  currentLang = currentLang === "gu" ? "en" : "gu";
  applyLanguage();
});

document.getElementById("logoutBtn").addEventListener("click", clearSession);

document.getElementById("navTabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
});

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  try {
    const res = await api("/api/v1/auth/register-tenant", "POST", payload);
    setSession(res.token, res.user);
    showToast("Isolated tenant created successfully!");
  } catch (err) { alert(err.message); }
});

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  try {
    const res = await api("/api/v1/auth/login", "POST", payload);
    setSession(res.token, res.user);
  } catch (err) { alert(err.message); }
});

document.getElementById("assetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/v1/assets", "POST", Object.fromEntries(new FormData(e.target).entries()));
    e.target.reset();
    showToast("Asset registered & logged to audit chain.");
    loadAllData();
  } catch (err) { showToast(err.message, true); }
});

document.getElementById("riskForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/v1/risks", "POST", Object.fromEntries(new FormData(e.target).entries()));
    e.target.reset();
    showToast("Risk scored & saved.");
    loadAllData();
  } catch (err) { showToast(err.message, true); }
});

document.getElementById("eventForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/v1/soc/events", "POST", Object.fromEntries(new FormData(e.target).entries()));
    e.target.reset();
    showToast(res.correlated_case_id ? `Event ingested & auto-correlated Case #${res.correlated_case_id}!` : "Security event ingested.");
    loadAllData();
  } catch (err) { showToast(err.message, true); }
});

document.getElementById("evidenceForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/v1/evidence", "POST", Object.fromEntries(new FormData(e.target).entries()));
    e.target.reset();
    showToast(`Evidence #${res.id} sealed! SHA-256: ${res.sha256_hash.slice(0, 16)}...`);
    loadAllData();
  } catch (err) { showToast(err.message, true); }
});

document.getElementById("verifyAuditBtn").addEventListener("click", async () => {
  try {
    const res = await api("/api/v1/audit/verify");
    showToast(res.valid ? `Audit Chain VERIFIED (${res.checked_entries} entries intact).` : `TAMPER DETECTED at ID #${res.broken_at_id}!`, !res.valid);
  } catch (err) { showToast(err.message, true); }
});

applyLanguage();
renderAppState();
