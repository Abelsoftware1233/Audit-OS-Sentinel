const API_BASE = "";

// ---------- tab switching ----------
const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".panel");

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    panels.forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`panel-${tab.dataset.tab}`).classList.add("active");
    if (tab.dataset.tab === "history") loadHistory();
  });
});

// ---------- elements ----------
const targetInput = document.getElementById("targetInput");
const modeSelect = document.getElementById("modeSelect");
const rangeFields = document.getElementById("rangeFields");
const rangeStart = document.getElementById("rangeStart");
const rangeEnd = document.getElementById("rangeEnd");
const consentRow = document.getElementById("consentRow");
const consentCheck = document.getElementById("consentCheck");
const externalAuthCard = document.getElementById("externalAuthCard");
const externalAuthCheck = document.getElementById("externalAuthCheck");
const ownerStatement = document.getElementById("ownerStatement");
const scanBtn = document.getElementById("scanBtn");
const errorBox = document.getElementById("errorBox");
const resultsCard = document.getElementById("resultsCard");
const resultsSummary = document.getElementById("resultsSummary");
const resultsDuration = document.getElementById("resultsDuration");
const findingsList = document.getElementById("findingsList");
const emptyState = document.getElementById("emptyState");
const loadingCard = document.getElementById("loadingCard");
const hardeningEmpty = document.getElementById("hardeningEmpty");
const hardeningList = document.getElementById("hardeningList");
const connStatus = document.getElementById("connStatus");
const historyBody = document.getElementById("historyBody");
const historyEmpty = document.getElementById("historyEmpty");
const reportBtn = document.getElementById("reportBtn");

let lastFindings = [];
let lastScanMeta = null;

// ---------- helpers ----------
// ---------- target classification (client-side heuristic — server is authoritative) ----------
function isLoopbackInput(value) {
  const v = value.trim().toLowerCase();
  return v === "127.0.0.1" || v === "localhost" || v.startsWith("127.");
}

function isPrivateInput(value) {
  const v = value.trim();
  if (/^10\./.test(v)) return true;
  if (/^192\.168\./.test(v)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(v)) return true;
  return false;
}

function classifyInput(value) {
  if (isLoopbackInput(value)) return "loopback";
  if (isPrivateInput(value)) return "private";
  return "external"; // publiek IP of domeinnaam — niet met zekerheid client-side te bepalen
}

function updateScopeVisibility() {
  const cls = classifyInput(targetInput.value);
  consentRow.hidden = cls !== "private";
  externalAuthCard.hidden = cls !== "external";
  if (cls !== "private") consentCheck.checked = false;
  if (cls !== "external") {
    externalAuthCheck.checked = false;
    ownerStatement.value = "";
  }
}

targetInput.addEventListener("input", updateScopeVisibility);
updateScopeVisibility();

modeSelect.addEventListener("change", () => {
  rangeFields.hidden = modeSelect.value !== "range";
});

function setError(msg) {
  if (!msg) {
    errorBox.hidden = true;
    errorBox.textContent = "";
    return;
  }
  errorBox.hidden = false;
  errorBox.textContent = msg;
}

function setConnStatus(state, label) {
  const dot = connStatus.querySelector(".dot");
  dot.className = "dot dot-" + state;
  connStatus.lastChild.textContent = " " + label;
}

// ---------- backend health check ----------
async function checkBackend() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (res.ok) {
      setConnStatus("ok", "backend: verbonden");
    } else {
      setConnStatus("err", "backend: fout");
    }
  } catch (e) {
    setConnStatus("err", "backend: niet bereikbaar (start app.py)");
  }
}
checkBackend();

// ---------- scan ----------
scanBtn.addEventListener("click", async () => {
  setError(null);
  const target = targetInput.value.trim() || "127.0.0.1";
  const mode = modeSelect.value;
  const cls = classifyInput(target);

  if (cls === "private" && !consentCheck.checked) {
    setError("Bevestig eerst dat je toestemming hebt om dit doelwit te scannen.");
    return;
  }

  if (cls === "external") {
    if (!externalAuthCheck.checked) {
      setError("Bevestig dat je eigenaar of beheerder bent van dit doelwit.");
      return;
    }
    if (ownerStatement.value.trim().length < 5) {
      setError("Vul een eigenaarsverklaring in (bv. bedrijfsnaam of domein).");
      return;
    }
  }

  const body = {
    target,
    mode,
    consent: cls === "private" ? consentCheck.checked : cls === "external" ? true : false,
    external_authorized: cls === "external" ? externalAuthCheck.checked : false,
    owner_statement: cls === "external" ? ownerStatement.value.trim() : "",
    range_start: parseInt(rangeStart.value, 10) || 1,
    range_end: parseInt(rangeEnd.value, 10) || 1024,
  };

  scanBtn.disabled = true;
  resultsCard.hidden = true;
  loadingCard.hidden = false;

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();

    if (!res.ok) {
      setError(data.error || "Onbekende fout bij scannen.");
      return;
    }

    renderResults(data);
    lastFindings = data.findings;
    lastScanMeta = {
      target: data.target,
      resolved_ip: data.resolved_ip,
      scope: data.scope,
      mode: data.mode,
      ports_scanned: data.ports_scanned,
      duration_ms: data.duration_ms,
      owner_confirmed: data.owner_confirmed,
      owner_statement: data.owner_statement,
      timestamp: data.timestamp,
    };
    renderHardening(data.findings);
  } catch (e) {
    setError("Kan geen verbinding maken met de backend. Draait app.py?");
  } finally {
    scanBtn.disabled = false;
    loadingCard.hidden = true;
  }
});

function renderResults(data) {
  resultsCard.hidden = false;
  const scopeLabels = { loopback: "localhost", private: "privénetwerk", public: "publiek (geautoriseerd)" };
  const scopeLabel = scopeLabels[data.scope] || data.scope;
  resultsSummary.textContent = `${data.findings.length} open poort(en) van ${data.ports_scanned} gescand op ${data.target} (${scopeLabel})`;
  resultsDuration.textContent = `${data.duration_ms} ms`;
  reportBtn.hidden = false;

  findingsList.innerHTML = "";
  if (data.findings.length === 0) {
    emptyState.hidden = false;
    return;
  }
  emptyState.hidden = true;

  data.findings.forEach((f) => {
    const el = document.createElement("div");
    el.className = `finding risk-${f.risk}`;
    el.innerHTML = `
      <span class="port">${f.port}</span>
      <span class="service">${escapeHtml(f.service)}</span>
      <span class="note">${escapeHtml(f.note)}${f.banner ? `<span class="banner">${escapeHtml(f.banner)}</span>` : ""}</span>
      <span class="risk-badge risk-${f.risk}">${f.risk}</span>
    `;
    findingsList.appendChild(el);
  });
}

reportBtn.addEventListener("click", async () => {
  if (!lastScanMeta) return;
  reportBtn.disabled = true;
  reportBtn.textContent = "Rapport genereren…";
  try {
    const res = await fetch(`${API_BASE}/api/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...lastScanMeta, findings: lastFindings }),
    });
    if (!res.ok) throw new Error("report failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-audit-report-${lastScanMeta.target.replace(/\./g, "-")}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    setError("Kon het PDF-rapport niet genereren.");
  } finally {
    reportBtn.disabled = false;
    reportBtn.textContent = "⬇ Download PDF-rapport";
  }
});

// ---------- hardening ----------
async function renderHardening(findings) {
  if (!findings || findings.length === 0) {
    hardeningEmpty.hidden = false;
    hardeningList.innerHTML = "";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/hardening`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings }),
    });
    const data = await res.json();
    hardeningEmpty.hidden = true;
    hardeningList.innerHTML = "";

    data.suggestions.forEach((s) => {
      const el = document.createElement("div");
      el.className = "hardening-item";
      el.innerHTML = `
        <div class="h-head">
          <span class="h-title"><span class="port">#${s.port}</span> ${escapeHtml(s.service)}</span>
          <span class="risk-badge risk-${s.risk}">${s.risk}</span>
        </div>
        <div class="cmd-row">
          <span class="cmd-label">Linux (ufw)</span>
          <code>${escapeHtml(s.commands.linux_ufw)}</code>
          <button class="copy-btn" data-cmd="${escapeAttr(s.commands.linux_ufw)}">Kopieer</button>
        </div>
        <div class="cmd-row">
          <span class="cmd-label">Linux (iptables)</span>
          <code>${escapeHtml(s.commands.linux_iptables)}</code>
          <button class="copy-btn" data-cmd="${escapeAttr(s.commands.linux_iptables)}">Kopieer</button>
        </div>
        <div class="cmd-row">
          <span class="cmd-label">Windows</span>
          <code>${escapeHtml(s.commands.windows_firewall)}</code>
          <button class="copy-btn" data-cmd="${escapeAttr(s.commands.windows_firewall)}">Kopieer</button>
        </div>
      `;
      hardeningList.appendChild(el);
    });

    hardeningList.querySelectorAll(".copy-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await navigator.clipboard.writeText(btn.dataset.cmd);
        btn.textContent = "Gekopieerd";
        btn.classList.add("copied");
        setTimeout(() => {
          btn.textContent = "Kopieer";
          btn.classList.remove("copied");
        }, 1500);
      });
    });
  } catch (e) {
    hardeningEmpty.hidden = false;
    hardeningEmpty.textContent = "Kon geen suggesties laden.";
  }
}

// ---------- history ----------
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const data = await res.json();
    historyBody.innerHTML = "";

    if (!data.history || data.history.length === 0) {
      historyEmpty.hidden = false;
      return;
    }
    historyEmpty.hidden = true;

    data.history.forEach((h) => {
      const tr = document.createElement("tr");
      const ts = new Date(h.timestamp).toLocaleString("nl-NL");
      const scopeLabels = { loopback: "localhost", private: "privé", public: "publiek ✓" };
      tr.innerHTML = `
        <td>${ts}</td>
        <td>${escapeHtml(h.target)}</td>
        <td>${escapeHtml(scopeLabels[h.scope] || h.scope || "")}</td>
        <td>${escapeHtml(h.mode)}</td>
        <td>${h.ports_scanned}</td>
        <td>${h.open_ports}</td>
        <td>${h.high_risk_count}</td>
        <td>${h.duration_ms} ms</td>
      `;
      historyBody.appendChild(tr);
    });
  } catch (e) {
    historyEmpty.hidden = false;
    historyEmpty.textContent = "Kon geschiedenis niet laden.";
  }
}

// ---------- utils ----------
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function escapeAttr(str) {
  return (str ?? "").replace(/"/g, "&quot;");
}
