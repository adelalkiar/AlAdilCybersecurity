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
    <tr data-id="${d.id}">
      <td><span class="badge ${d.overall_threat_level}">${THREAT_LABELS[d.overall_threat_level] || d.overall_threat_level}</span></td>
      <td>${d.hostname || "جهاز غير معروف"}${d.is_unidentified ? ' <span class="badge info">مجهول</span>' : ""}${d.identity_spoof_suspected ? ' <span class="badge spoof-alert">⚠ انتحال محتمل</span>' : ""}</td>
      <td>${d.ip_address || "—"}</td>
      <td>${d.mac_address || "—"}<br><small>${d.vendor || ""}</small></td>
      <td>${d.connection_medium}</td>
      <td>${d.access_likelihood_score.toFixed(0)}%</td>
      <td>${d.potential_damage_score.toFixed(0)}%</td>
      <td><span class="badge intruder-${d.intruder_status}">${INTRUDER_LABELS[d.intruder_status] || d.intruder_status}</span></td>
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
      <h4>${v.cve_id ? `${v.cve_id} — ` : ""}${v.title} <span class="badge ${v.severity}">${THREAT_LABELS[v.severity] || v.severity}</span></h4>
      <p>${v.description || ""}</p>
      ${v.recommended_fix ? `<div class="fix">الحل الموصى به: ${v.recommended_fix}</div>` : ""}
      ${v.added_by_user ? `<small>أُضيفت يدويًا من قبل محلل</small>` : ""}
    </div>
  `).join("") || "<p>لا توجد ثغرات مكتشفة لهذا الجهاز.</p>";

  const exploitHtml = (d.exploitability_notes || [])
    .map((n) => `<div class="exploit-note">${n}</div>`).join("");

  const hostActivityHtml = (d.host_activity_notes || [])
    .map((n) => `<div class="exploit-note">${n}</div>`).join("");

  $("#modal-body").innerHTML = `
    <h2>${d.hostname || "جهاز غير معروف"} ${d.is_unidentified ? '<span class="badge info">مجهول</span>' : ""}</h2>
    ${d.identity_spoof_suspected ? `<div class="identity-alert">⚠ <b>اشتباه انتحال هوية:</b> ${d.identity_spoof_note}</div>` : ""}
    <p><b>IP:</b> ${d.ip_address || "—"} &nbsp; <b>MAC:</b> ${d.mac_address || "—"} &nbsp; <b>الشركة:</b> ${d.vendor || "—"}</p>
    <p><b>النوع:</b> ${d.device_type} &nbsp; <b>وسيلة الاتصال:</b> ${d.connection_medium}</p>
    <p><b>احتمالية الوصول:</b> ${d.access_likelihood_score.toFixed(0)}% &nbsp;
       <b>الضرر المحتمل:</b> ${d.potential_damage_score.toFixed(0)}%</p>
    <p><b>محاولات فاشلة:</b> ${d.failed_connection_attempts} &nbsp;
       <b>محاولات ناجحة:</b> ${d.successful_connection_attempts}</p>
    ${d.accessed_host_system ? `<p>🔴 <b>هذا الجهاز دخل إلى جهاز النظام نفسه</b></p>` : ""}
    ${d.unusual_data_transfer_detected ? `<p>🔴 <b>رُصد نقل بيانات غير معتاد من جهاز النظام</b></p>` : ""}
    ${hostActivityHtml}
    <h3>المنافذ المفتوحة</h3>
    <ul>${(d.open_ports || []).map((p) => `<li>${p.port}/${p.protocol} — ${p.service || "غير معروف"}</li>`).join("") || "<li>لا توجد منافذ مفتوحة مكتشفة</li>"}</ul>
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
        <b>${l.customer_name}</b> — ${l.customer_email}
        <div class="meta">
          الأجهزة: ${l.activated_agents_count}/${l.max_agents} &nbsp;|&nbsp;
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

$("#login-btn").addEventListener("click", login);
$("#password").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
$("#refresh-btn").addEventListener("click", loadDevices);
$("#filter-threat").addEventListener("change", loadDevices);
$("#filter-intruder").addEventListener("change", loadDevices);
$("#filter-unidentified").addEventListener("change", loadDevices);
$("#filter-spoof").addEventListener("change", loadDevices);
$("#modal-close").addEventListener("click", () => $("#device-modal").classList.add("hidden"));

if (token) showApp();
