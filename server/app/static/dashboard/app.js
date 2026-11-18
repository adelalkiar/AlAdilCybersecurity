const API = "";
let token = localStorage.getItem("aladil_token") || null;

const THREAT_LABELS = {
  critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة",
};
const INTRUDER_LABELS = {
  active_threat: "تهديد نشط",
  dormant_ineffective: "محاولات غير فعّالة",
  blocked: "محظور",
  none: "لا يوجد",
};

function $(sel) { return document.querySelector(sel); }

// يُعقِّم أي نص قبل إدراجه في innerHTML - إلزامي لكل حقل يرد من الخادم
// (hostname، vendor، عناوين الثغرات...) لأن الكثير منها قابل للتحكم به
// فعليًا من أي جهاز على الشبكة (اسم شبكة WiFi، اسم جهاز mDNS/Bluetooth)
// قبل أن يصل أصلًا لقاعدة البيانات - بلا هذا التعقيم يصبح ذلك XSS مخزَّن.
function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(API + path, { ...options, headers });
  if (res.status === 401) {
    logout();
    throw new Error("جلسة منتهية");
  }
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function logout() {
  token = null;
  localStorage.removeItem("aladil_token");
  $("#app-screen").classList.add("hidden");
  $("#login-screen").classList.remove("hidden");
}

async function login() {
  const username = $("#username").value.trim();
  const password = $("#password").value;
  $("#login-error").textContent = "";
  try {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(API + "/api/auth/login", { method: "POST", body });
    if (!res.ok) throw new Error("فشل تسجيل الدخول");
    const data = await res.json();
    token = data.access_token;
    localStorage.setItem("aladil_token", token);
    showApp();
  } catch (e) {
    $("#login-error").textContent = "بيانات الدخول غير صحيحة";
  }
}

function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#app-screen").classList.remove("hidden");
  loadDevices();
}

function renderSummary(devices) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  devices.forEach((d) => counts[d.overall_threat_level] = (counts[d.overall_threat_level] || 0) + 1);
  const cards = [
    ["critical", "حرجة"], ["high", "مرتفعة"], ["medium", "متوسطة"], ["low", "منخفضة"], ["info", "معلوماتية"],
  ];
  $("#summary-cards").innerHTML = cards.map(([level, label]) => `
    <div class="card ${level}">
      <div class="count">${counts[level] || 0}</div>
      <div class="label">أجهزة بخطورة ${label}</div>
    </div>
  `).join("");
}

function renderRows(devices) {
  $("#device-rows").innerHTML = devices.map((d) => `
    <tr data-id="${esc(d.id)}">
      <td><span class="badge ${esc(d.overall_threat_level)}">${esc(THREAT_LABELS[d.overall_threat_level] || d.overall_threat_level)}</span></td>
      <td>${esc(d.hostname) || "جهاز غير معروف"}${d.is_unidentified ? ' <span class="badge info">مجهول</span>' : ""}${d.identity_spoof_suspected ? ' <span class="badge spoof-alert">⚠ انتحال محتمل</span>' : ""}</td>
      <td>${esc(d.ip_address) || "—"}</td>
      <td>${esc(d.mac_address) || "—"}<br><small>${esc(d.vendor)}</small></td>
      <td>${esc(d.connection_medium)}</td>
      <td>${d.access_likelihood_score.toFixed(0)}%</td>
      <td>${d.potential_damage_score.toFixed(0)}%</td>
      <td><span class="badge intruder-${esc(d.intruder_status)}">${esc(INTRUDER_LABELS[d.intruder_status] || d.intruder_status)}</span></td>
      <td>${new Date(d.last_seen).toLocaleString("ar")}</td>
    </tr>
  `).join("");

  document.querySelectorAll("#device-rows tr").forEach((row) => {
    row.addEventListener("click", () => openDevice(row.dataset.id));
  });
}

async function loadDevices() {
  const threat = $("#filter-threat").value;
  const intruder = $("#filter-intruder").value;
  const params = new URLSearchParams();
  if (threat) params.set("threat_level", threat);
  if (intruder) params.set("intruder_status", intruder);
  if ($("#filter-unidentified").checked) params.set("unidentified_only", "true");
  if ($("#filter-spoof").checked) params.set("identity_spoof_only", "true");

  try {
    const devices = await api("/api/devices?" + params.toString());
    renderSummary(devices);
    renderRows(devices);
  } catch (e) {
    console.error(e);
  }
}

async function openDevice(id) {
  const d = await api(`/api/devices/${id}`);
  const vulnsHtml = (d.vulnerabilities || []).map((v) => `
    <div class="vuln-item">
      <h4>${v.cve_id ? `${esc(v.cve_id)} — ` : ""}${esc(v.title)} <span class="badge ${esc(v.severity)}">${esc(THREAT_LABELS[v.severity] || v.severity)}</span></h4>
      <p>${esc(v.description)}</p>
      ${v.recommended_fix ? `<div class="fix">الحل الموصى به: ${esc(v.recommended_fix)}</div>` : ""}
      ${v.added_by_user ? `<small>أُضيفت يدويًا من قبل محلل</small>` : ""}
    </div>
  `).join("") || "<p>لا توجد ثغرات مكتشفة لهذا الجهاز.</p>";

  const exploitHtml = (d.exploitability_notes || [])
    .map((n) => `<div class="exploit-note">${esc(n)}</div>`).join("");

  const hostActivityHtml = (d.host_activity_notes || [])
    .map((n) => `<div class="exploit-note">${esc(n)}</div>`).join("");

  $("#modal-body").innerHTML = `
    <h2>${esc(d.hostname) || "جهاز غير معروف"} ${d.is_unidentified ? '<span class="badge info">مجهول</span>' : ""}</h2>
    ${d.identity_spoof_suspected ? `<div class="identity-alert">⚠ <b>اشتباه انتحال هوية:</b> ${esc(d.identity_spoof_note)}</div>` : ""}
    <p><b>IP:</b> ${esc(d.ip_address) || "—"} &nbsp; <b>MAC:</b> ${esc(d.mac_address) || "—"} &nbsp; <b>الشركة:</b> ${esc(d.vendor) || "—"}</p>
    <p><b>النوع:</b> ${esc(d.device_type)} &nbsp; <b>وسيلة الاتصال:</b> ${esc(d.connection_medium)}</p>
    <p><b>احتمالية الوصول:</b> ${d.access_likelihood_score.toFixed(0)}% &nbsp;
       <b>الضرر المحتمل:</b> ${d.potential_damage_score.toFixed(0)}%</p>
    <p><b>محاولات فاشلة:</b> ${d.failed_connection_attempts} &nbsp;
       <b>محاولات ناجحة:</b> ${d.successful_connection_attempts}</p>
    ${d.accessed_host_system ? `<p>🔴 <b>هذا الجهاز دخل إلى جهاز النظام نفسه</b></p>` : ""}
    ${d.unusual_data_transfer_detected ? `<p>🔴 <b>رُصد نقل بيانات غير معتاد من جهاز النظام</b></p>` : ""}
    ${hostActivityHtml}
    <h3>المنافذ المفتوحة</h3>
    <ul>${(d.open_ports || []).map((p) => `<li>${esc(p.port)}/${esc(p.protocol)} — ${esc(p.service) || "غير معروف"}</li>`).join("") || "<li>لا توجد منافذ مفتوحة مكتشفة</li>"}</ul>
    ${exploitHtml ? `<h3>ملاحظات قابلية الاستغلال</h3>${exploitHtml}` : ""}
    <h3>الثغرات</h3>
    ${vulnsHtml}
  `;
  $("#device-modal").classList.remove("hidden");
}

const DURATION_LABELS = {
  minute: "دقيقة", hour: "ساعة", day: "يوم", week: "أسبوع", month: "شهر", year: "سنة",
};

async function loadLicenses() {
  try {
    const licenses = await api("/api/licenses");
    $("#lic-list").innerHTML = licenses.map((l) => `
      <div class="lic-row">
        <b>${esc(l.customer_name)}</b> — ${esc(l.customer_email)}
        <div class="meta">
          الأجهزة: ${esc(l.activated_agents_count)}/${esc(l.max_agents)} &nbsp;|&nbsp;
          ينتهي: ${l.expires_at ? new Date(l.expires_at).toLocaleString("ar") : "بلا انتهاء"}
          ${l.revoked ? ' &nbsp;<span class="badge critical">ملغى</span>' : ""}
        </div>
      </div>
    `).join("") || "<p>لا توجد تراخيص صادرة بعد.</p>";
  } catch (e) {
    $("#lic-list").innerHTML = "<p>تعذّر تحميل التراخيص.</p>";
  }
}

async function issueLicense() {
  const params = new URLSearchParams({
    customer_name: $("#lic-customer-name").value.trim(),
    customer_email: $("#lic-customer-email").value.trim(),
    max_agents: $("#lic-max-agents").value || "1",
    duration_count: $("#lic-duration-count").value || "1",
    duration_unit: $("#lic-duration-unit").value,
  });
  try {
    const result = await api("/api/licenses?" + params.toString(), { method: "POST" });
    $("#lic-result").textContent = `تم الإصدار (ينتهي ${new Date(result.expires_at).toLocaleString("ar")}): ${result.license_key}`;
    loadLicenses();
  } catch (e) {
    $("#lic-result").textContent = "فشل إصدار الترخيص.";
  }
}

$("#licenses-btn").addEventListener("click", () => {
  $("#licenses-modal").classList.remove("hidden");
  loadLicenses();
});
$("#licenses-close").addEventListener("click", () => $("#licenses-modal").classList.add("hidden"));
$("#lic-issue-btn").addEventListener("click", issueLicense);
$("#lic-duration-unit").addEventListener("change", () => {
  $("#lic-duration-count").disabled = $("#lic-duration-unit").value === "lifetime";
});

async function changePassword() {
  const current_password = $("#pwd-current").value;
  const new_password = $("#pwd-new").value;
  const confirm = $("#pwd-confirm").value;
  $("#pwd-result").textContent = "";
  if (new_password !== confirm) {
    $("#pwd-result").textContent = "كلمة المرور الجديدة وتأكيدها غير متطابقين.";
    return;
  }
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password, new_password }),
    });
    $("#pwd-result").textContent = "تم تغيير كلمة المرور بنجاح.";
    $("#pwd-current").value = "";
    $("#pwd-new").value = "";
    $("#pwd-confirm").value = "";
  } catch (e) {
    $("#pwd-result").textContent = "فشل تغيير كلمة المرور - تحقق من كلمة المرور الحالية.";
  }
}

$("#change-password-btn").addEventListener("click", () => $("#password-modal").classList.remove("hidden"));
$("#password-close").addEventListener("click", () => $("#password-modal").classList.add("hidden"));
$("#pwd-save-btn").addEventListener("click", changePassword);

const LEVEL_LABELS = { danger: "خطير", suspect: "مشبوه", review: "للمراجعة" };

function renderFinding(f) {
  const connectionsHtml = (f.processes || []).flatMap((p) => p.connections || []).map((c) => `
    <li>${esc(c.ra)}:${esc(c.rp)}</li>
  `).join("");
  const launchersHtml = (f.launchers || []).map((l) => `
    <li>${esc(l.type === "task" ? "مهمة مجدولة" : "تشغيل تلقائي")}: ${esc(l.name)}${l.hidden ? " (مخفية)" : ""}${l.level ? ` — صلاحية: ${esc(l.level)}` : ""}</li>
  `).join("");
  const processesHtml = (f.processes || []).map((p) => `
    <li>PID ${esc(p.pid)} — ${esc(p.name)}${p.cmd ? ` — <code>${esc(p.cmd)}</code>` : ""}</li>
  `).join("");
  return `
    <div class="vuln-item">
      <h4>
        <span class="badge ${esc(f.level)}">${esc(LEVEL_LABELS[f.level] || f.level)} (${esc(f.score)}/100)</span>
        ${esc(f.display_name)}
      </h4>
      <p><b>المسار:</b> ${esc(f.path)}</p>
      <p><b>التوقيع:</b> ${esc(f.signature_status) || "—"} ${f.signer ? `— ${esc(f.signer)}` : ""}</p>
      ${f.company || f.product || f.description ? `<p><b>الشركة/المنتج:</b> ${esc(f.company)} ${esc(f.product)} ${esc(f.description)}</p>` : ""}
      ${f.owner ? `<p><b>مالك الملف:</b> ${esc(f.owner)}</p>` : ""}
      ${f.sha256 ? `<p><b>SHA-256:</b> <code>${esc(f.sha256)}</code></p>` : ""}
      ${f.zone_name ? `<p><b>مصدر التنزيل:</b> ${esc(f.zone_name)}${f.zone_host_url ? ` — ${esc(f.zone_host_url)}` : ""}</p>` : ""}
      ${f.created || f.modified ? `<p><b>تاريخ الإنشاء/التعديل:</b> ${esc(f.created)} / ${esc(f.modified)}</p>` : ""}
      ${f.has_encrypted_sibling ? `<p>⚠ يوجد ملف مجاور يبدو مشفَّرًا (حمولة مخفية محتملة)</p>` : ""}
      ${f.urls && f.urls.length ? `<p><b>روابط مضمَّنة:</b> ${f.urls.map(esc).join("، ")}</p>` : ""}
      ${f.ips && f.ips.length ? `<p><b>عناوين IP مضمَّنة:</b> ${f.ips.map(esc).join("، ")}</p>` : ""}
      ${launchersHtml ? `<p><b>مصدر التشغيل:</b></p><ul>${launchersHtml}</ul>` : ""}
      ${processesHtml ? `<p><b>العمليات الحالية:</b></p><ul>${processesHtml}</ul>` : ""}
      ${connectionsHtml ? `<p><b>اتصالات شبكية:</b></p><ul>${connectionsHtml}</ul>` : ""}
      <p><b>الأسباب:</b></p>
      <ul>${(f.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
    </div>
  `;
}

async function loadHostScan() {
  $("#host-scan-list").innerHTML = "<p>جارٍ التحميل...</p>";
  try {
    const agentsList = await api("/api/agents");
    const allFindings = agentsList.flatMap((a) =>
      (a.unsigned_program_findings || []).map((f) => ({ ...f, _agent: a.hostname || a.id }))
    );
    if (!allFindings.length) {
      $("#host-scan-list").innerHTML = "<p>لا توجد نتائج بعد - ستظهر هنا بعد أول دورة فحص من الوكيل.</p>";
      return;
    }
    allFindings.sort((a, b) => b.score - a.score);
    $("#host-scan-list").innerHTML = allFindings.map((f) => `
      <p class="hint"><b>الجهاز:</b> ${esc(f._agent)}</p>
      ${renderFinding(f)}
    `).join("");
  } catch (e) {
    $("#host-scan-list").innerHTML = "<p>تعذّر تحميل النتائج.</p>";
  }
}

$("#host-scan-btn").addEventListener("click", () => {
  $("#host-scan-modal").classList.remove("hidden");
  loadHostScan();
});
$("#host-scan-close").addEventListener("click", () => $("#host-scan-modal").classList.add("hidden"));

const SEVERITY_LABELS = { critical: "حرجة", high: "مرتفعة", medium: "متوسطة", low: "منخفضة" };

function renderAuditFinding(f) {
  const manualHtml = (f.manual_steps || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const badgeClass = { critical: "critical", high: "high", medium: "medium", low: "info" }[f.severity] || "info";
  return `
    <div class="vuln-item">
      <h4>
        <span class="badge ${badgeClass}">${esc(SEVERITY_LABELS[f.severity] || f.severity)}</span>
        ${esc(f.title)}
      </h4>
      <p><b>الدليل:</b> ${esc(f.evidence)}</p>
      <p><b>ما يستطيعه المهاجم:</b> ${esc(f.impact)}</p>
      ${f.fix_command ? `
        <div class="fix">
          <b>أمر الإصلاح (نفّذه أنت كمسؤول):</b>
          <pre class="cmd-box">${esc(f.fix_command)}</pre>
          ${f.needs_reboot ? `<p>⚠ يتطلب إعادة تشغيل بعد التنفيذ.</p>` : ""}
          <p class="hint">درجة خطورة الإصلاح: ${esc(f.fix_risk)}</p>
          ${f.undo_command ? `<details><summary>أمر التراجع</summary><pre class="cmd-box">${esc(f.undo_command)}</pre></details>` : ""}
        </div>` : ""}
      ${manualHtml ? `<p><b>خطوات يدوية:</b></p><ul>${manualHtml}</ul>` : ""}
    </div>
  `;
}

async function loadAudit() {
  $("#audit-list").innerHTML = "<p>جارٍ التحميل...</p>";
  try {
    const agentsList = await api("/api/agents");
    const allFindings = agentsList.flatMap((a) =>
      (a.security_audit_findings || []).map((f) => ({ ...f, _agent: a.hostname || a.id }))
    );
    if (!allFindings.length) {
      $("#audit-list").innerHTML = "<p>لا توجد نتائج بعد - ستظهر هنا بعد أول دورة تدقيق من الوكيل.</p>";
      return;
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    $("#audit-list").innerHTML = allFindings.map((f) => `
      <p class="hint"><b>الجهاز:</b> ${esc(f._agent)}</p>
      ${renderAuditFinding(f)}
    `).join("");
  } catch (e) {
    $("#audit-list").innerHTML = "<p>تعذّر تحميل نتائج التدقيق.</p>";
  }
}

$("#audit-btn").addEventListener("click", () => {
  $("#audit-modal").classList.remove("hidden");
  loadAudit();
});
$("#audit-close").addEventListener("click", () => $("#audit-modal").classList.add("hidden"));

async function loadTrustedNetworks() {
  try {
    const entries = await api("/api/trusted-networks");
    $("#tn-list").innerHTML = entries.map((e) => `
      <div class="lic-row">
        <b>${esc(e.label)}</b> — ${esc(e.cidr_or_host)}
        <div class="meta">${esc(e.note)}</div>
        <button class="tn-cmd-btn" data-cidr="${esc(e.cidr_or_host)}">أمر جدار الحماية النموذجي</button>
        <button class="tn-del-btn" data-id="${esc(e.id)}">حذف</button>
      </div>
    `).join("") || "<p>لا توجد شبكات موثوقة مضافة بعد.</p>";

    document.querySelectorAll(".tn-del-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await api(`/api/trusted-networks/${btn.dataset.id}`, { method: "DELETE" });
        loadTrustedNetworks();
      });
    });
    document.querySelectorAll(".tn-cmd-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const result = await api(`/api/trusted-networks/example-firewall-command?cidr_or_host=${encodeURIComponent(btn.dataset.cidr)}`);
        alert(result.command + "\n\n" + result.note);
      });
    });
  } catch (e) {
    $("#tn-list").innerHTML = "<p>تعذّر تحميل القائمة.</p>";
  }
}

async function addTrustedNetwork() {
  const label = $("#tn-label").value.trim();
  const cidr_or_host = $("#tn-cidr").value.trim();
  const note = $("#tn-note").value.trim();
  if (!label || !cidr_or_host) return;
  await api("/api/trusted-networks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label, cidr_or_host, note }),
  });
  $("#tn-label").value = "";
  $("#tn-cidr").value = "";
  $("#tn-note").value = "";
  loadTrustedNetworks();
}

$("#trusted-networks-btn").addEventListener("click", () => {
  $("#trusted-networks-modal").classList.remove("hidden");
  loadTrustedNetworks();
});
$("#trusted-networks-close").addEventListener("click", () => $("#trusted-networks-modal").classList.add("hidden"));
$("#tn-add-btn").addEventListener("click", addTrustedNetwork);

$("#login-btn").addEventListener("click", login);
$("#password").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
$("#refresh-btn").addEventListener("click", loadDevices);
$("#filter-threat").addEventListener("change", loadDevices);
$("#filter-intruder").addEventListener("change", loadDevices);
$("#filter-unidentified").addEventListener("change", loadDevices);
$("#filter-spoof").addEventListener("change", loadDevices);
$("#modal-close").addEventListener("click", () => $("#device-modal").classList.add("hidden"));

if (token) showApp();
