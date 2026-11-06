const $ = (id) => document.getElementById(id);
const state = { by: "hour", page: 0, pageSize: 15 };
const charts = {};

const GREEN = "#39ff14", GREEN_DIM = "#1f8a0c", RED = "#ff4d4d";
const SEV_COLORS = { low: "#7d8782", medium: "#e0b040", high: "#ff7b3a", critical: "#ff4d4d" };

Chart.defaults.color = "#9aa59f";
Chart.defaults.borderColor = "#232826";
Chart.defaults.font.family = "'JetBrains Mono', 'Fira Code', Consolas, monospace";

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node[k] = v;
  }
  kids.flat().forEach((c) =>
    node.append(c instanceof Node ? c : document.createTextNode(c ?? "")));
  return node;
}

const fmt = (iso) => (iso ? iso.slice(0, 19).replace("T", " ") : "-");
const badge = (sev) => el("span", { class: `badge sev-${sev}` }, sev);

function renderTable(id, headers, rows, onRow) {
  const box = $(id);
  if (!rows.length) {
    box.replaceChildren(el("p", { class: "empty" }, "No data yet."));
    return;
  }
  const head = el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h))));
  const body = el("tbody", {}, rows.map((cells, i) => {
    const tr = el("tr", onRow ? { class: "clickable" } : {}, cells.map((c) => el("td", {}, c)));
    if (onRow) tr.addEventListener("click", () => onRow(i));
    return tr;
  }));
  box.replaceChildren(el("table", {}, head, body));
}

function qs(extra = {}) {
  const p = new URLSearchParams();
  for (const id of ["start", "end", "ip"]) {
    const v = $(id).value.trim();
    if (v) p.set(id, v);
  }
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return p.toString();
}

async function api(path, extra = {}) {
  const r = await fetch(`/api/${path}?${qs(extra)}`);
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function showError(msg) {
  const box = $("error");
  box.textContent = msg;
  box.classList.toggle("hidden", !msg);
}

function draw(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), config);
}

const baseOpts = { responsive: true, maintainAspectRatio: false };

async function loadStatus() {
  const r = await fetch("/api/honeypot/status");
  const s = await r.json();
  $("hp-dot").className = "dot " + (s.listening ? "up" : "down");
  $("hp-text").textContent = s.listening
    ? `Honeypot listening :${s.port}`
    : `Honeypot DOWN (port ${s.port})`;
}

async function loadSummary() {
  const s = await api("summary");
  const o = s.overview;
  $("c-connections").textContent = o.total_connections;
  $("c-failed").textContent = o.failed_logins;
  $("c-success").textContent = o.successful_logins;
  $("c-ips").textContent = o.unique_ips;
  $("c-attacks").textContent = o.detected_attacks;
  $("c-alerts").textContent = o.total_alerts;

  renderTable("t-attackers",
    ["IP", "Failed", "Events", "First seen", "Last seen", "Alert severity"],
    s.top_ips.map((i) => [i.source_ip, i.failed_logins, i.events,
                          fmt(i.first_seen), fmt(i.last_seen), badge(i.max_severity)]),
    (i) => { $("ip").value = s.top_ips[i].source_ip; refreshAll(); });

  draw("ch-users", {
    type: "bar",
    data: { labels: s.top_usernames.map((u) => u.username),
            datasets: [{ label: "Attempts", data: s.top_usernames.map((u) => u.count),
                         backgroundColor: GREEN_DIM, borderColor: GREEN, borderWidth: 1 }] },
    options: { ...baseOpts, indexAxis: "y", plugins: { legend: { display: false } },
               scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
  });

  renderTable("t-passwords", ["Password (masked)", "Attempts"],
    s.top_passwords.map((p) => [p.password_masked, p.count]));

  const sev = s.alerts.by_severity;
  const names = Object.keys(sev);
  draw("ch-sev", {
    type: "doughnut",
    data: { labels: names, datasets: [{ data: names.map((n) => sev[n]),
            backgroundColor: names.map((n) => SEV_COLORS[n]), borderColor: "#141815" }] },
    options: { ...baseOpts, plugins: { legend: { position: "bottom" } } },
  });

  const ss = s.sessions;
  $("s-total").textContent = ss.total;
  $("s-avg").textContent = ss.avg_duration_s;
  $("s-max").textContent = ss.max_duration_s;
  $("s-cmds").textContent = ss.total_commands;
  renderTable("t-sessions", ["Session", "IP", "Started", "Duration (s)", "Commands"],
    ss.recent.map((r) => [r.id, r.source_ip, fmt(r.start_time), r.duration_s, r.commands_count]));
}

async function loadTimeline() {
  const t = await api("timeline", { by: state.by });
  draw("ch-timeline", {
    type: "bar",
    data: { labels: t.labels, datasets: [
      { label: "Failed", data: t.failed, backgroundColor: GREEN_DIM, borderColor: GREEN, borderWidth: 1 },
      { label: "Success", data: t.success, backgroundColor: RED },
    ] },
    options: { ...baseOpts, scales: { x: { stacked: true },
               y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } },
  });
}

function statusSelect(alert) {
  const options = ["open", "investigating", "closed", "false_positive"]
    .map((s) => el("option", { value: s, selected: s === alert.status }, s));
  const sel = el("select", {}, options);
  sel.addEventListener("change", async () => {
    const r = await fetch(`/api/alerts/${alert.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: sel.value }),
    });
    showError(r.ok ? "" : "Could not update the alert status");
  });
  return sel;
}

async function loadAlerts() {
  const extra = { limit: 50 };
  if ($("f-sev").value) extra.severity = $("f-sev").value;
  if ($("f-status").value) extra.status = $("f-status").value;
  const rows = await api("alerts", extra);
  renderTable("t-alerts", ["Time", "Severity", "Type", "IP", "Description", "Status"],
    rows.map((a) => [fmt(a.created_at), badge(a.severity), a.alert_type,
                     a.source_ip, a.description, statusSelect(a)]));
}

async function loadEvents() {
  const extra = { limit: state.pageSize, offset: state.page * state.pageSize };
  if ($("f-type").value) extra.event_type = $("f-type").value;
  const d = await api("attacks", extra);
  renderTable("t-events", ["Time", "Type", "IP", "User", "Password", "Command"],
    d.items.map((e) => [fmt(e.timestamp), e.event_type, e.source_ip,
                        e.username, e.password_masked, e.command]),
    (i) => showDetail(d.items[i].id));
  const from = d.total ? d.offset + 1 : 0;
  const to = d.offset + d.items.length;
  $("pager-info").textContent = `${from}-${to} of ${d.total}`;
  $("prev").disabled = state.page === 0;
  $("next").disabled = to >= d.total;
}

async function showDetail(id) {
  try {
    const d = await api(`attacks/${id}`);
    const kv = (k, v) => el("div", { class: "kv" },
      el("span", { class: "k" }, k), el("span", {}, v ?? "-"));
    const box = $("detail");
    box.classList.remove("hidden");
    box.replaceChildren(
      el("h3", {}, `Event #${d.event.id}`),
      kv("Type", d.event.event_type), kv("Time", fmt(d.event.timestamp)),
      kv("Source IP", d.event.source_ip), kv("Session", d.event.session_id),
      kv("Session duration", d.session ? `${d.session.duration_s ?? "-"} s` : "-"),
      kv("Commands in session", d.session ? d.session.commands_count : "-"),
      el("h4", {}, "Session timeline"),
      el("ul", {}, d.session_events.map((e) => el("li", {},
        `${fmt(e.timestamp)}  ${e.event_type}` +
        (e.username ? `  user=${e.username}` : "") +
        (e.password_masked ? `  pw=${e.password_masked}` : "") +
        (e.command ? `  $ ${e.command}` : "")))),
      el("h4", {}, "Alerts for this IP"),
      el("ul", {}, d.ip_alerts.map((a) =>
        el("li", {}, `${fmt(a.created_at)}  [${a.severity}] ${a.alert_type}  (${a.status})`))),
    );
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) { showError(e.message); }
}

function updateLinks() {
  const q = qs();
  $("dl-attacks").href = "/api/export/attacks.csv" + (q ? "?" + q : "");
  $("dl-report").href = "/api/report?download=1" + (q ? "&" + q : "");
}

async function refreshAll() {
  showError("");
  updateLinks();
  try {
    await Promise.all([loadStatus(), loadSummary(), loadTimeline(), loadAlerts(), loadEvents()]);
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (e) { showError(e.message); }
}

$("filters").addEventListener("submit", (e) => { e.preventDefault(); state.page = 0; refreshAll(); });
$("reset").addEventListener("click", () => {
  ["start", "end", "ip"].forEach((id) => { $(id).value = ""; });
  state.page = 0; refreshAll();
});
document.querySelectorAll("[data-by]").forEach((b) => b.addEventListener("click", () => {
  state.by = b.dataset.by;
  document.querySelectorAll("[data-by]").forEach((x) => x.classList.toggle("active", x === b));
  loadTimeline().catch((e) => showError(e.message));
}));
$("f-sev").addEventListener("change", () => loadAlerts().catch((e) => showError(e.message)));
$("f-status").addEventListener("change", () => loadAlerts().catch((e) => showError(e.message)));
$("f-type").addEventListener("change", () => { state.page = 0; loadEvents().catch((e) => showError(e.message)); });
$("prev").addEventListener("click", () => { state.page -= 1; loadEvents(); });
$("next").addEventListener("click", () => { state.page += 1; loadEvents(); });

refreshAll();
setInterval(refreshAll, 30000);  