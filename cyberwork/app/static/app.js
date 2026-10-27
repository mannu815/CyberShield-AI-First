const $ = (id) => document.getElementById(id);
let latestScanId = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function requestJson(url, options={}) {
  const response = await fetch(url, options);
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function setOutput(id, html) { $(id).innerHTML = html; }
function box(title, body) { return `<div class="analysis-box"><h3>${title}</h3>${body}</div>`; }
function riskClass(risk) { return `risk-${String(risk || "low").toLowerCase()}`; }
function renderCounts(counts={}) {
  return ["Critical","High","Medium","Low","Informational"].map(s => `<div class="count-pill"><strong>${counts[s] || 0}</strong><small>${s}</small></div>`).join("");
}
function renderFindings(findings=[]) {
  if (!findings.length) return '<div class="empty-state"><strong>No findings returned</strong></div>';
  return findings.map(f => `<article class="finding"><div class="finding-top"><span class="severity ${escapeHtml(f.severity.toLowerCase())}">${escapeHtml(f.severity)}</span><h4>${escapeHtml(f.title)}</h4></div><p><b>Evidence:</b> ${escapeHtml(f.evidence)}</p><p><b>Recommendation:</b> ${escapeHtml(f.recommendation)}</p></article>`).join("");
}
function updateStats(counts={}) {
  $("stat-critical").textContent = counts.Critical ?? "—";
  $("stat-high").textContent = counts.High ?? "—";
  $("stat-medium").textContent = counts.Medium ?? "—";
}
const severityOrder = [
  ["Critical", "#ff626e"], ["High", "#ff9b62"], ["Medium", "#f7c66b"],
  ["Low", "#6a8cff"], ["Informational", "#4ce0d2"]
];
function drawSeverityChart(counts={}) {
  const canvas = $("severity-chart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const width = 320, height = 220;
  canvas.width = width * dpr; canvas.height = height * dpr;
  ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,width,height);
  const total = severityOrder.reduce((sum,[key]) => sum + Number(counts[key] || 0), 0);
  const cx=105, cy=110, radius=76, thickness=22;
  ctx.lineWidth=thickness; ctx.lineCap="round";
  if (!total) {
    ctx.beginPath(); ctx.strokeStyle="#253247"; ctx.arc(cx,cy,radius,0,Math.PI*2); ctx.stroke();
    ctx.fillStyle="#eef4ff"; ctx.font="600 24px sans-serif"; ctx.textAlign="center"; ctx.fillText("—",cx,cy+2);
    ctx.fillStyle="#9aabc3"; ctx.font="11px sans-serif"; ctx.fillText("No scan yet",cx,cy+22);
  } else {
    let angle=-Math.PI/2;
    severityOrder.forEach(([key,color]) => {
      const value=Number(counts[key]||0); if(!value) return;
      const next=angle+(value/total)*Math.PI*2;
      ctx.beginPath();ctx.strokeStyle=color;ctx.arc(cx,cy,radius,angle,next-0.025);ctx.stroke();angle=next;
    });
    ctx.fillStyle="#eef4ff";ctx.font="700 26px sans-serif";ctx.textAlign="center";ctx.fillText(String(total),cx,cy+1);
    ctx.fillStyle="#9aabc3";ctx.font="11px sans-serif";ctx.fillText("findings",cx,cy+21);
  }
  const legend=$("severity-legend");
  legend.innerHTML=severityOrder.map(([key,color])=>`<span><i class="legend-dot" style="background:${color}"></i>${key==="Informational"?"Info":key} <b>${Number(counts[key]||0)}</b></span>`).join("");
  $("chart-state").textContent=total ? `${total} finding${total===1?"":"s"}` : "Waiting for scan";
}
function tickClock() {
  const el=$("local-clock"); if(el) el.textContent=new Date().toLocaleTimeString();
}
drawSeverityChart(); tickClock(); setInterval(tickClock,1000);
window.addEventListener("resize",()=>drawSeverityChart(window.latestSeverityCounts||{}));
function renderApplicationModules(report={}) {
  const host = $("application-test-coverage");
  if (!host) return;
  const modules = report.modules || [];
  if (!modules.length) { host.innerHTML = '<div class="empty-state">No module coverage details were returned.</div>'; return; }
  const labels = {
    checked_limited_observations: "LIMITED CHECK RAN",
    not_run_in_passive_mode: "NOT RUN IN PASSIVE MODE",
    partially_checked: "PARTIALLY CHECKED",
    requires_manual_or_staging_test: "MANUAL / STAGING REQUIRED"
  };
  host.innerHTML = modules.map(m => `<article class="finding"><div class="finding-top"><span class="severity ${m.result === 'checked_limited_observations' ? 'low' : 'info'}">${escapeHtml(labels[m.result] || m.result || 'STATUS UNKNOWN')}</span><h4>${escapeHtml(m.name)}</h4></div><p><b>Checks:</b> ${escapeHtml((m.checks || []).join('; '))}</p><p><b>Status evidence:</b> ${escapeHtml(m.evidence || '')}</p><p><b>Limitations:</b> ${escapeHtml(m.limits || '')}</p></article>`).join("");
}
function showScan(result) {
  window.latestSeverityCounts = result.counts || {};
  drawSeverityChart(window.latestSeverityCounts);
  latestScanId = result.id ?? latestScanId;
  $("result-empty").hidden = true;
  $("result-content").hidden = false;
  $("result-target").textContent = result.final_url || result.target || "Target";
  $("result-code").textContent = `HTTP ${result.status_code ?? "—"} · ${result.duration_ms ?? "—"} ms`;
  $("result-status").textContent = "Scan complete";
  $("result-counts").innerHTML = renderCounts(result.counts);
  $("findings-list").innerHTML = renderFindings(result.findings);
  renderApplicationModules(result.application_test_modules || {});
  updateStats(result.counts || {});
}
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("scan-button");
  button.disabled = true; button.textContent = "Scanning…";
  $("scan-status").textContent = "Validating target and running limited passive checks…";
  try {
    const form = new FormData();
    form.append("target", $("target").value);
    if ($("authorized").checked) form.append("authorized", "on");
    form.append("mode", $("scan-mode").value);
    if ($("scan-mode").value === "authorized") form.append("scope_confirmation", $("scope-confirmation").value.trim());
    const result = await requestJson("/api/scans", {method:"POST", body:form});
    showScan(result);
    $("scan-status").textContent = "Scan completed. Review evidence and validate findings before taking action.";
    await refreshHistory();
  } catch (error) { $("scan-status").textContent = error.message; }
  finally { button.disabled = false; button.innerHTML = 'Run passive scan <span>→</span>'; }
});
$("export-latest").addEventListener("click", () => {
  if (!latestScanId) { $("scan-status").textContent = "Run a scan first to export a saved report."; return; }
  window.location.href = `/api/scans/${latestScanId}/export`;
});
$("export-latest-pdf").addEventListener("click", () => {
  if (!latestScanId) { $("scan-status").textContent = "Run a scan first to export a PDF report."; return; }
  window.location.href = `/api/scans/${latestScanId}/report.pdf`;
});
$("scan-mode").addEventListener("change", () => {
  const advanced = $("scan-mode").value === "authorized";
  $("scope-confirmation-wrap").hidden = !advanced;
  $("scan-button").innerHTML = advanced ? 'Run authorized checks <span>→</span>' : 'Run security checks <span>→</span>';
});
$("url-form").addEventListener("submit", async (event) => {
  event.preventDefault(); setOutput("url-output", '<p class="muted">Analyzing URL indicators…</p>');
  try {
    const data = await requestJson("/api/analyze-url", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url:$("url-input").value})});
    setOutput("url-output", box(`Risk: <span class="${riskClass(data.risk)}">${escapeHtml(data.risk)}</span> · score ${data.score}`, `<ul>${data.checks.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul><p class="muted">${escapeHtml(data.note || "")}</p>`));
  } catch(e) { setOutput("url-output", box("Could not analyze", `<p>${escapeHtml(e.message)}</p>`)); }
});
$("message-form").addEventListener("submit", async (event) => {
  event.preventDefault(); setOutput("message-output", '<p class="muted">Checking text indicators…</p>');
  try {
    const data = await requestJson("/api/analyze-message", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({message:$("message-input").value})});
    setOutput("message-output", box(`Risk: <span class="${riskClass(data.risk)}">${escapeHtml(data.risk)}</span> · score ${data.score}`, `<p><b>Indicators</b></p><ul>${data.indicators.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul><p><b>Safety tips</b></p><ul>${data.recommendations.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul>`));
  } catch(e) { setOutput("message-output", box("Could not analyze", `<p>${escapeHtml(e.message)}</p>`)); }
});
$("osint-form").addEventListener("submit", async (event) => {
  event.preventDefault(); setOutput("osint-output", '<p class="muted">Resolving public DNS…</p>');
  try {
    const data = await requestJson("/api/osint", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({domain:$("domain-input").value})});
    setOutput("osint-output", box(`DNS results: ${escapeHtml(data.domain)}`, `<ul>${(data.ip_addresses || []).map(ip=>`<li><code>${escapeHtml(ip)}</code></li>`).join("") || "<li>No IP addresses returned.</li>"}</ul><p class="muted">${escapeHtml(data.note)}</p>`));
  } catch(e) { setOutput("osint-output", box("Lookup failed", `<p>${escapeHtml(e.message)}</p>`)); }
});
async function refreshAssistantStatus() {
  const badge = $("assistant-provider");
  if (!badge) return;
  try {
    const data = await requestJson("/api/assistant/status", {cache:"no-store"});
    badge.textContent = data.provider || "Built-in fallback";
    badge.title = `Gemini configured: ${data.gemini_configured}; Ollama available: ${data.ollama_available}`;
  } catch { badge.textContent = "Status unavailable"; }
}
refreshAssistantStatus();
$("assistant-form")?.addEventListener("submit", async (event) => {
  event.preventDefault(); const question = $("question-input").value.trim(); if (!question) return;
  const send = event.submitter; if (send) { send.disabled = true; send.textContent = "Working…"; }
  setOutput("assistant-output", '<p class="muted">Thinking or running an approved local tool…</p>');
  try {
    const data = await requestJson("/api/assistant", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({question})});
    setOutput("assistant-output", box(escapeHtml(data.mode || "Assistant response"), `<p style="white-space:pre-wrap">${escapeHtml(data.answer)}</p><p class="muted">${escapeHtml(data.note || "")}</p>`));
  } catch(e) { setOutput("assistant-output", box("Could not respond", `<p>${escapeHtml(e.message)}</p>`)); }
  finally { if (send) { send.disabled = false; send.textContent = "Send message ↗"; } refreshAssistantStatus(); }
});
async function refreshHistory() {
  const body = $("history-body");
  try {
    const rows = await requestJson("/api/scans");
    $("stat-total").textContent = rows.length;
    if (!rows.length) { body.innerHTML = '<tr><td colspan="7" class="table-empty">No scans saved yet.</td></tr>'; return; }
    body.innerHTML = rows.map(r => `<tr><td class="target-cell">${escapeHtml(r.target)}</td><td>${escapeHtml((r.created_at||"").slice(0,19).replace("T"," "))}</td><td>${escapeHtml(r.status_code ?? "—")}</td><td>${escapeHtml(r.duration_ms ?? "—")} ms</td><td>${r.counts?.Medium || 0}</td><td>${r.counts?.High || 0}</td><td><button class="text-button" data-load="${r.id}">View</button> <a class="text-button" href="/api/scans/${r.id}/export">JSON</a></td></tr>`).join("");
  } catch(e) { console.error(e); }
}
$("refresh-history").addEventListener("click", refreshHistory);
$("history-body").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-load]");
  if (!button) return;
  try { const result = await requestJson(`/api/scans/${button.dataset.load}`); result.id = Number(button.dataset.load); showScan(result); $("scanner").scrollIntoView({behavior:"smooth"}); }
  catch(e) { alert(e.message); }
});
refreshHistory();


let vulnerabilityCatalogCache = [];
$("load-catalog")?.addEventListener("click", async () => {
  const out = $("catalog-output");
  out.innerHTML = '<p class="muted">Loading catalog…</p>';
  try {
    const data = await requestJson("/api/vulnerability-catalog");
    vulnerabilityCatalogCache = data.items || [];
    $("catalog-summary").innerHTML = `<p><b>${vulnerabilityCatalogCache.length}</b> vulnerability/bug categories. Entries not marked as assessed have not been tested by this scanner.</p>`;
    renderCatalog();
  } catch (e) { out.innerHTML = `<p class="muted">${escapeHtml(e.message)}</p>`; }
});
function renderCatalog() {
  const term = ($("catalog-search")?.value || "").toLowerCase().trim();
  const rows = vulnerabilityCatalogCache.filter(x => `${x.name} ${x.category} ${x.assessment_type}`.toLowerCase().includes(term));
  $("catalog-output").innerHTML = `<p class="muted">Showing ${rows.length} of ${vulnerabilityCatalogCache.length} entries.</p><div class="table-wrap"><table><thead><tr><th>Category</th><th>Vulnerability / bug</th><th>Test type</th></tr></thead><tbody>${rows.slice(0,250).map(x => `<tr><td>${escapeHtml(x.category)}</td><td>${escapeHtml(x.name)}</td><td>${escapeHtml(x.assessment_type.replaceAll("_"," "))}</td></tr>`).join("")}</tbody></table></div>`;
}
$("catalog-search")?.addEventListener("input", renderCatalog);
$("cve-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("cve-output"); out.innerHTML = '<p class="muted">Querying NIST NVD…</p>';
  try {
    const id = encodeURIComponent($("cve-input").value.trim().toUpperCase());
    const d = await requestJson(`/api/cve/${id}`);
    out.innerHTML = `<div class="finding"><div class="finding-top"><span class="severity ${riskClass(d.severity || "Informational")}">${escapeHtml(d.severity || "Unscored")}</span><h4>${escapeHtml(d.id)}</h4></div><p>${escapeHtml(d.description)}</p><p><b>CVSS:</b> ${escapeHtml(d.cvss_score ?? "Not available")} · <b>Published:</b> ${escapeHtml(d.published || "Unknown")}</p><p class="muted">Source: NIST NVD. This record has not been matched to a target asset.</p></div>`;
  } catch(e) { out.innerHTML = `<p class="muted">${escapeHtml(e.message)}</p>`; }
});


// Safe attack-defense lab: returns a defensive test plan only; never targets a live host.
(() => {
  const form = document.getElementById('lab-form');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const out = document.getElementById('lab-output');
    const button = document.getElementById('lab-run');
    button.disabled = true; out.textContent = 'Preparing safe simulation…';
    try {
      const result = await requestJson('/api/lab/simulate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({scenario:document.getElementById('lab-scenario').value, notes:document.getElementById('lab-context').value})});
      out.innerHTML = `<article class="finding"><div class="finding-top"><span class="severity info">${escapeHtml(result.status)}</span><h4>${escapeHtml(result.title)}</h4></div><p><b>Defensive validation steps</b></p><ul>${result.steps.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ul><p><b>Remediation:</b> ${escapeHtml(result.remediation)}</p><p class="form-note">${escapeHtml(result.note)}</p></article>`;
    } catch (error) { out.textContent = error.message || 'Simulation request failed.'; }
    finally { button.disabled = false; }
  });
})();
