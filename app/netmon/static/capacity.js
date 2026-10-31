// Capacity planner, Resources & capacity, device Hardware & capacity. Data: /netmon/api/capacity/*.
(() => {
  const { $, fmtBytes, fmtBps, ago, fmtTime } = NM;
  // NM.el sets attributes only; event handlers must be listeners (the CSP blocks inline handlers)
  const el = (tag, attrs = {}, ...kids) => { const { onclick, oninput, ...rest } = attrs || {}; const n = NM.el(tag, rest, ...kids);
    if (typeof onclick === "function") n.addEventListener("click", onclick); if (typeof oninput === "function") n.addEventListener("input", oninput); return n; };
  const root = $("cap"); if (!root) return;
  const view = root.dataset.view, role = document.querySelector('meta[name="nm-role"]')?.content || "viewer";
  const csrf = document.querySelector('meta[name="nm-csrf"]')?.content || "";
  const admin = role === "admin", analyst = role === "admin" || role === "analyst";
  const num = (v, d = 0) => v == null || Number.isNaN(+v) ? "unknown" : (+v).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: 0 });
  const pct = (v, d = 0) => v == null ? "unknown" : `${(100 * v).toFixed(d)}%`;
  const lab = (l) => el("span", { class: `lab ${l || "UNKNOWN"}`, text: l || "UNKNOWN", title: LABEL_HELP[l || "UNKNOWN"] });
  const LABEL_HELP = { MEASURED: "Read from this installation", ESTIMATED: "Calculated with a documented model (docs/capacity-planning.md)",
    SUGGESTED: "Planning assumption, not a measurement", BENCHMARKED: "Measured by the benchmark harness on recorded hardware",
    MANUAL: "Entered by you", UNKNOWN: "Not available: never shown as zero" };
  const card = (title, sub, ...kids) => el("section", { class: "card" }, el("div", { class: "card-h" }, el("h2", { text: title }), sub ? el("span", { class: "muted small", text: sub }) : null), ...kids);
  const kv = (rows) => el("table", { class: "tbl kv" }, el("tbody", {}, rows.filter(Boolean).map(([k, v, l, note]) =>
    el("tr", {}, el("th", { text: k }), el("td", {}, v), el("td", {}, l ? lab(l) : ""), el("td", { class: "muted small", text: note || "" })))));
  const errBox = (node, e) => node.replaceChildren(el("div", { class: "state error", text: `Could not load: ${e.message}` }));
  async function post(url, body) {
    const r = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF": csrf }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.statusText); return j;
  }
  const stat = (s, f = (x) => num(x, 1)) => !s || s.label !== "MEASURED" ? "unknown" : `${f(s.avg)} avg · ${f(s.p95)} P95 · ${f(s.peak)} peak ${s.peak_interval || "1-minute"} rate`;

  if (view === "planner") planner();
  if (view === "resources") resources();
  if (view === "device") device();

  // =================================================================== planner
  function planner() {
    const body = $("capbody");
    const st = { mode: null, window: "7d", ov: null, inputs: {}, labels: {}, retention: {}, headroom: 30, reserve: 15, answers: {}, calc: null };
    root.querySelectorAll("[data-mode]").forEach((b) => b.addEventListener("click", () => choose(b.dataset.mode)));
    load();

    async function load(refresh = false, range) {
      body.replaceChildren(el("p", { class: "muted", text: "Loading measurements… (reads up to 30 days of per-minute data)" }));
      try {
        const q = range ? `start=${range[0]}&end=${range[1]}` : `window=${st.window}`;
        st.ov = await NM.get(`/netmon/api/capacity/overview?${q}${refresh ? "&refresh=1" : ""}`);
        const p = st.ov.plan || {};
        if (!st.mode) { st.mode = p.mode || (st.ov.observe.flows.label === "MEASURED" ? "existing" : "new");
          Object.assign(st, { answers: p.answers || {}, retention: p.retention || {}, headroom: p.headroom ?? 30, reserve: p.reserve ?? 15 });
          if (p.inputs && p.labels) { for (const [k, v] of Object.entries(p.inputs)) if (p.labels[k] === "MANUAL") { st.inputs[k] = v; st.labels[k] = "MANUAL"; } } }
        render();
      } catch (e) { errBox(body, e); }
    }

    function choose(mode) {
      if (mode === "existing") {
        const manual = Object.keys(st.labels).filter((k) => st.labels[k] === "MANUAL");
        if (manual.length && st.mode === "existing" &&
          confirm(`You changed ${manual.length} value(s) by hand (${manual.join(", ")}).\n\nOK = replace them with live measurements\nCancel = keep your values`)) {
          st.inputs = {}; st.labels = {};
        }
      }
      st.mode = mode; render();
      root.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
    }

    function render() {
      const ov = st.ov; if (!ov) return;
      root.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("on", b.dataset.mode === st.mode));
      body.replaceChildren(serverCard(ov), st.mode === "new" ? wizard() : measuredCard(ov), el("div", { id: "capresults" }),
        envCard(ov), findingsCard(ov), calibCard(ov));
      recalc();
    }

    // ---- current server
    function serverCard(ov) {
      const i = ov.inventory, o = ov.observe;
      const nic = i.nics?.value ? i.nics.value.map((n) => `${n.name} ${n.speed_mbps > 0 ? (n.speed_mbps >= 1000 ? n.speed_mbps / 1000 + " GbE" : n.speed_mbps + " Mb/s") : "speed not reported"}`).join(", ") : null;
      const lines = [
        ["CPU", `${i.cpu_model?.value || "model unknown"} · ${i.logical_cpus?.value} vCPU${i.sockets?.value ? ` (${i.sockets.value} socket × ${i.cores_per_socket?.value} cores × ${i.threads_per_core?.value} threads)` : ""}`, i.cpu_model?.label,
          `${i.cpu_isa?.value || ""}${i.cpu_isa?.note ? " — " + i.cpu_isa.note : ""}`],
        ["RAM", `${fmtBytes(i.ram_total?.value)} installed · ${fmtBytes(i.ram_available?.value)} available now`, i.ram_total?.label, `swap ${fmtBytes(i.swap_total?.value || 0)}`],
        ["Storage", `${fmtBytes(i.clickhouse_disk_total?.value || i.disk_total?.value)} · ${fmtBytes(i.clickhouse_disk_free?.value || i.disk_free?.value)} free · ${i.disk_type?.value || "type unknown"}`,
          i.disk_type?.label, i.disk_type?.note],
        ["Network", nic || "unknown", i.nics?.label, i.nics?.note],
        ["Virtualization", i.hypervisor?.value || "unknown", i.hypervisor?.label, i.hypervisor?.note],
        ["Limits for m0nitor", limits(i.container_limits?.value), i.container_limits?.label, i.container_limits?.note],
        ["Host helper", i.host_helper?.value != null ? `updated ${ago(i.host_helper.value)}` : "not installed", i.host_helper?.label, i.host_helper?.note]];
      const now = [["CPU (P95 / avg)", `${pct(o.cpu.p95)} / ${pct(o.cpu.avg)}`, o.cpu.label], ["RAM in use (P95)", pct(o.mem.p95), o.mem.label],
        ["Disk used", pct(1 - (i.clickhouse_disk_free?.value || 0) / (i.clickhouse_disk_total?.value || 1)), i.clickhouse_disk_total?.label],
        ["Disk busy (P95)", pct(o.io_util.p95), o.io_util.label, o.block_device ? `device ${o.block_device}` : ""]];
      const fix = admin ? el("details", {}, el("summary", { text: "Correct detected values" }), correctForm(i)) : null;
      return card("Current m0nitor server", "installed resources and what m0nitor can actually use", gradeBox(ov.grade),
        el("div", { class: "grid2 even" }, el("div", {}, kv(lines)), el("div", {}, kv(now),
          el("p", { class: "row" }, el("button", { text: "Recalculate now", title: "Re-read hardware and re-measure (results are otherwise cached for 5 minutes)" }), " ", el("span", { class: "muted small", text: o.hardware_change?.mode === "projected" ? `CPU and memory projected from the previous hardware (${o.hardware_change.before.vcpus} → ${o.hardware_change.after.vcpus} vCPU, ${fmtBytes(o.hardware_change.before.ram_bytes)} → ${fmtBytes(o.hardware_change.after.ram_bytes)} RAM) until ${fmtTime(o.hardware_change.ready_at)}, when 6 hours on the new hardware have been measured` : o.hardware_change ? `measured over ${dur(o.window.t1 - o.window.resources_t0)} since the hardware change (${o.hardware_change.before.vcpus} → ${o.hardware_change.after.vcpus} vCPU, ${fmtBytes(o.hardware_change.before.ram_bytes)} → ${fmtBytes(o.hardware_change.after.ram_bytes)} RAM); workload over ${win(o.window)}` : `measured over ${win(o.window)}` })))), fix);
    }
    function gradeBox(g) {
      if (!g || g.value == null) return el("div", { class: "grade" }, el("span", { class: "grade-n unknown", text: "?" }),
        el("div", {}, el("b", { text: "Hardware grade unknown " }), lab("UNKNOWN"), el("div", { class: "muted small", text: g?.note || "" })));
      const names = { cpu: "CPU", memory: "memory", disk_io: "disk I/O", disk_space: "disk space" };
      const tone = g.value >= 75 ? "good" : g.value >= 50 ? "ok" : g.value >= 25 ? "warn" : "bad";
      const comps = Object.entries(g.components).sort((a, b) => a[1].score - b[1].score).map(([k, c]) =>
        el("span", { class: "chip", title: c.basis, text: `${names[k] || k} ${Math.round(c.score)} (${c.multiplier.toFixed(1)}×)` }));
      return el("div", { class: `grade ${tone}` }, el("span", { class: "grade-n", text: String(g.value), title: "0-100, 100 is best" }),
        el("div", {}, el("b", { text: `Hardware grade ${g.value}/100 — ${g.band}` }), " ", lab(g.label),
          el("div", { class: "small" }, `Limited by ${names[g.limited_by] || g.limited_by}. `, ...comps),
          el("div", { class: "muted small", text: `${g.note}. Confidence ${g.confidence}.${g.caps.length ? " " + g.caps.join("; ") + "." : ""}` })));
    }
    function limits(v) { if (!v) return "unknown"; const a = v.app || {};
      return `app container: CPU ${a.app_cpu ?? "no limit"}, memory ${a.app_memory ? fmtBytes(a.app_memory) : "no limit"}` +
        (v.containers ? ` · ${Object.entries(v.containers).map(([n, c]) => `${n}: ${c.cpus || "no CPU limit"}, ${c.memory ? fmtBytes(c.memory) : "no memory limit"}`).join("; ")}` : ""); }
    function correctForm(i) {
      const f = el("form", { method: "post", action: "/netmon/settings/capacity/server", class: "stackform" }, el("input", { type: "hidden", name: "csrf", value: csrf }));
      for (const [k, l] of [["cpu_model", "CPU model"], ["disk_type", "Disk type (e.g. NVMe SSD, Ceph RBD)"], ["nics", "Network (e.g. 2x 10 GbE)"], ["hypervisor", "Hypervisor"]])
        f.append(el("label", {}, l, el("input", { name: k, value: i[k]?.label === "MANUAL" ? i[k].value : "", placeholder: i[k]?.detected ?? i[k]?.value ?? "" })));
      f.append(el("button", { text: "Save corrections" }), el("p", { class: "muted small", text: "Leave a field empty to use the detected value. Detected values stay visible beside yours." }));
      return f;
    }
    const dur = (sec) => sec < 2 * 86400 ? `${(sec / 3600).toFixed(1)} hours` : `${(sec / 86400).toFixed(1)} days`;
    const win = (w) => `${((w.t1 - w.t0) / 86400).toFixed(1)} days${w.note ? ` (${w.note})` : ""}`;

    // ---- mode A / C
    function measuredCard(ov) {
      const o = ov.observe, c = o.counts, adv = st.mode === "advanced";
      const ws = el("div", { class: "seg" }, ["1h", "24h", "7d", "30d"].map((w) => el("button", { text: w, class: st.window === w ? "on" : "", onclick: () => { st.window = w; load(); } })));
      const cf = el("input", { type: "datetime-local", class: "short" }), ct = el("input", { type: "datetime-local", class: "short" });
      const custom = el("span", { class: "row" }, "custom ", cf, " – ", ct, el("button", { text: "Apply", onclick: () => {
        const a = Date.parse(cf.value) / 1000, b = Date.parse(ct.value) / 1000; if (a && b && b > a) load(false, [a, b]); } }));
      const meas = [["Flow records/s", o.flows], ["Stored log events/s", o.events], ["DNS events/s", o.event_tables?.dns_events],
        ["WAN throughput (SNMP)", o.throughput_snmp, (x) => fmtBps(x)], ["WAN throughput (flow-estimated)", o.throughput_flow, (x) => fmtBps(x)],
        ["Host CPU", o.cpu, (x) => pct(x)], ["Host memory", o.mem, (x) => pct(x)], ["Disk busy time", o.io_util, (x) => pct(x)],
        ["Disk writes", o.write_Bps, (x) => fmtBytes(x) + "/s"], ["Disk latency per I/O", o.io_latency_ms, (x) => num(x, 1) + " ms"]];
      const mt = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["Measurement", "Average", "P95", "Peak (1-min)", "Samples", "Period", "Missing", "Freshness", "Confidence", ""].map((h) => el("th", { text: h })))),
        el("tbody", {}, meas.filter((m) => m[1]).map(([n, s, f = (x) => num(x, 1)]) => el("tr", {}, el("td", { text: n }),
          ...(s.label === "MEASURED" ? [f(s.avg), f(s.p95), `${f(s.peak)}${s.peak_at ? " at " + fmtTime(s.peak_at, true) : ""}`, num(s.samples), `${num(s.observed_hours, 1)} h`,
            s.missing?.length ? `${s.missing.length} gap(s), ${num(s.missing.reduce((a, g) => a + (g[1] - g[0]), 0) / 60)} min` : "none",
            ago(s.freshness_s), `${s.confidence} (${s.confidence_reason})`].map((x) => el("td", { text: x }))
            : [el("td", { colspan: 8, class: "muted", text: s.note || "no measurements" })]), el("td", {}, lab(s.label))))));
      const fields = [["firewalls", "Firewalls", c.firewalls, "MEASURED"], ["devices", "Devices (all)", c.devices, "MEASURED"], ["exporters", "Active flow exporters", c.active_exporters, c.active_exporters == null ? "UNKNOWN" : "MEASURED"],
        ["interfaces", "Active interfaces in flows", c.active_interfaces, c.active_interfaces == null ? "UNKNOWN" : "MEASURED"],
        ["flows_avg", "Average flow records/s", o.flows.avg, o.flows.label], ["flows_p95", "P95 flow records/s", o.flows.p95, o.flows.label],
        ["events_avg", "Average log events/s", o.events.avg, o.events.label], ["events_p95", "P95 log events/s", o.events.p95, o.events.label],
        ["dns_avg", "Average DNS events/s", o.event_tables?.dns_events?.avg, o.event_tables?.dns_events?.label || "UNKNOWN"],
        ["snmp", "SNMP objects polled per minute", c.snmp_oids_per_minute, "MEASURED"]];
      if (adv) fields.push(["bytes_per_flow", "Bytes stored per flow record", (ov.storage.find((t) => t.group === "Raw flows") || {}).bytes_per_row, "MEASURED"],
        ["storage_overhead_pct", "Extra storage overhead %", 0, "MANUAL"], ["sampling", "Flow sampling ratio (1:N)", null, "UNKNOWN"],
        ["active_timeout", "Flow active timeout (s)", null, "UNKNOWN"], ["packet_rate", "Packet rate (packets/s)", null, "UNKNOWN"], ["snmp_interval", "SNMP interval (s)", 10, "MEASURED"]);
      const editable = new Set(["flows_avg", "flows_p95", "events_avg", "events_p95", "dns_avg", "bytes_per_flow", "storage_overhead_pct", "sampling", "active_timeout", "packet_rate", "snmp_interval"]);
      const ft = el("table", { class: "tbl" }, el("tbody", {}, fields.map(([k, n, v, l]) => {
        const cur = st.inputs[k] ?? v, label = st.labels[k] || l;
        const input = editable.has(k) ? el("input", { type: "number", min: 0, step: "any", value: cur == null ? "" : +(+cur).toFixed(2), class: "short", placeholder: "unknown" }) : el("b", { text: num(cur, 1) });
        if (input.tagName === "INPUT") input.addEventListener("input", () => { st.inputs[k] = input.value === "" ? null : +input.value; st.labels[k] = "MANUAL"; tag.replaceChildren(lab("MANUAL")); debounce(recalc); });
        const tag = el("span", {}, lab(label));
        return el("tr", {}, el("th", { text: n }), el("td", {}, input), el("td", {}, tag), el("td", { class: "muted small", text: label === "MANUAL" && v != null ? `measured: ${num(v, 1)}` : "" }));
      })));
      const reset = el("button", { text: "Reset fields to live observations", onclick: () => { st.inputs = {}; st.labels = {}; render(); } });
      const feats = Object.entries(c.features || {}).map(([k, on]) => el("span", { class: `chip ${on ? "on" : ""}`, text: `${on ? "✓" : "○"} ${k.replace("_", " ")}` }));
      const advNote = adv ? el("p", { class: "muted small", text: "Sampling, active timeout and packet rate are recorded with the plan and shown in the report; the storage and CPU outputs use the record rates, bytes per record and overhead entered here." }) : null;
      return card(adv ? "Advanced / manual settings" : "Existing installation — measured load", `Source: this m0nitor installation · window: ${win(o.window)}`,
        el("div", { class: "row" }, ws, custom), el("div", { class: "wrap" }, mt),
        el("p", { class: "muted small", text: "Averages exclude telemetry gaps (≥10 empty minutes) and time before collection started; short quiet periods count as zero. Peaks are the busiest 1-minute rate, not an instantaneous value." }),
        el("h3", { text: "Calculator inputs" }), el("div", { class: "wrap" }, ft), advNote, el("p", { class: "row" }, reset, analyst ? el("button", { text: "Save plan", onclick: save }) : null),
        el("p", {}, el("b", { text: "Active features: " }), ...feats));
    }

    // ---- mode B
    function wizard() {
      const a = st.answers;
      const q = (k, label, opts, def) => el("label", {}, label, (() => { const s = el("select", { name: k }, opts.map(([v, t]) => el("option", { value: v, text: t, selected: (a[k] ?? def) === v })));
        s.addEventListener("change", () => { a[k] = s.value; }); if (a[k] == null) a[k] = def; return s; })());
      const n = el("input", { type: "number", min: 1, max: 5000, value: a.devices || 1, class: "short" }); n.addEventListener("input", () => { a.devices = +n.value || 1; });
      if (a.devices == null) a.devices = 1;
      const featList = [["flows", "Flow monitoring"], ["syslog", "Syslog"], ["snmp", "SNMP"], ["ids", "IDS/IPS alerts"], ["dns", "DNS events"], ["behavioral", "Behavioral detection"],
        ["threat_intel", "Threat intelligence"], ["zeek", "Zeek (optional)"], ["ai", "AI analysis"]];
      a.features = a.features || ["flows", "syslog", "snmp", "ids", "behavioral"];
      const feats = el("div", { class: "chips" }, featList.map(([k, t]) => { const c = el("input", { type: "checkbox", checked: a.features.includes(k) });
        c.addEventListener("change", () => { a.features = c.checked ? [...new Set([...a.features, k])] : a.features.filter((x) => x !== k); }); return el("label", { class: "chip" }, c, " ", t); }));
      const speeds = [["100", "100 Mbps"], ["500", "500 Mbps"], ["1000", "1 Gbps"], ["2500", "2.5 Gbps"], ["5000", "5 Gbps"], ["10000", "10 Gbps"], ["25000", "25 Gbps"], ["40000", "40 Gbps"], ["100000", "100 Gbps"], ["", "Custom / unknown"]];
      const custom = el("input", { type: "number", min: 1, class: "short", placeholder: "Mb/s", value: a.link_custom || "" }); custom.addEventListener("input", () => { a.link_custom = +custom.value || null; });
      const form = el("div", { class: "wizard" },
        q("network", "1. What type of network are you monitoring?", [["home_lab", "Home lab"], ["small_office", "Small office"], ["medium", "Medium business"], ["msp", "MSP / multiple client networks"], ["datacenter", "Data center"], ["enterprise", "Enterprise"]], "small_office"),
        el("label", {}, "2. Approximately how many firewalls or routers?", n),
        el("label", {}, "3. Approximate internet connection speed (per firewall)", (() => { const s = el("select", {}, speeds.map(([v, t]) => el("option", { value: v, text: t, selected: String(a.link_mbps ?? "1000") === v }))); s.addEventListener("change", () => { a.link_mbps = s.value ? +s.value : null; }); if (a.link_mbps === undefined) a.link_mbps = 1000; return s; })(), custom),
        q("activity", "4. How busy is the network?", [["light", "Light"], ["typical", "Typical"], ["heavy", "Heavy"], ["very_heavy", "Very heavy"], ["unknown", "Unknown"]], "typical"),
        q("detail", "5. How much monitoring detail?", [["lightweight", "Lightweight"], ["balanced", "Balanced (recommended)"], ["detailed", "Detailed"]], "balanced"),
        q("retention_days", "6. How long should data be kept?", [7, 14, 30, 60, 90, 180, 365].map((d) => [String(d), `${d} days`]), "30"),
        el("div", {}, el("span", { text: "7. Which features will you use?" }), feats));
      const go = el("button", { class: "primary", text: "Use suggested values", onclick: () => { if (!a.link_mbps && a.link_custom) a.link_mbps = a.link_custom; recalc(); } });
      const cal = Object.keys(st.ov.calibration.ratios || {}).length;
      return card("Plan a new installation", "plain questions only: no flow or event rates needed", form, el("p", { class: "row" }, go, analyst ? el("button", { text: "Save plan", onclick: save }) : null),
        el("p", { class: "muted small", text: cal ? "Ranges are calibrated with ratios measured on this installation (shown with the results). They are planning values, not measurements." :
          "Ranges come from documented generic assumptions (docs/capacity-planning.md). They are not measurements or vendor figures." }));
    }

    // ---- results
    let tmr; const debounce = (f) => { clearTimeout(tmr); tmr = setTimeout(f, 350); };
    async function recalc() {
      const node = $("capresults"); if (!node) return;
      try {
        const answers = { ...st.answers, link_mbps: st.answers.link_mbps || st.answers.link_custom || 1000 };
        st.calc = await post("/netmon/api/capacity/calc", { mode: st.mode, window: st.window, inputs: st.inputs, retention: st.retention, headroom: st.headroom, reserve: st.reserve, answers });
        node.replaceChildren(...(st.mode === "new" ? newResults(st.calc) : existingResults(st.calc)));
      } catch (e) { errBox(node, e); }
    }

    function existingResults(r) {
      const c = r.capacity, d = r.disk || {}, ov = st.ov;
      const fc = c.flows_capacity || {}, ec = c.events_capacity || {};
      const b = c.bottleneck || {};
      const knobs = el("div", { class: "row" },
        el("label", {}, "Keep CPU headroom ", (() => { const i = el("input", { type: "number", min: 0, max: 90, value: st.headroom, class: "short" }); i.addEventListener("input", () => { st.headroom = +i.value; debounce(recalc); }); return i; })(), " %"),
        el("label", {}, "Free-space reserve ", (() => { const i = el("input", { type: "number", min: 0, max: 50, value: st.reserve, class: "short" }); i.addEventListener("input", () => { st.reserve = +i.value; debounce(recalc); }); return i; })(), " %"));
      const capRows = [
        ["Sustained flow ingestion", fc.value != null ? `${num(fc.value)} records/s${fc.range ? ` (range ${num(fc.range[0])}–${num(fc.range[1])})` : ""}` : "unknown", fc.label, fc.note],
        ["Peak ingestion", fc.value != null ? `short bursts above the sustained rate are absorbed by Kafka (buffered, not dropped) while lag stays bounded` : "unknown", fc.value != null ? "ESTIMATED" : "UNKNOWN", ""],
        ["Log event processing", ec.value != null ? `${num(ec.value)} events/s` : "unknown", ec.label, ec.note],
        ["CPU at the rates entered", r.cpu_at_inputs?.value != null ? `${pct(r.cpu_at_inputs.value)} ${r.cpu_at_inputs.fits ? "(fits)" : "(over target)"}` : "unknown", r.cpu_at_inputs?.label, r.cpu_at_inputs?.note],
        ["CPU headroom", pct(c.cpu_headroom?.value), c.cpu_headroom?.label, c.cpu_headroom?.note],
        ["RAM headroom", pct(c.ram_headroom?.value), c.ram_headroom?.label, c.ram_headroom?.note],
        ["Disk I/O headroom", pct(c.io_headroom?.value), c.io_headroom?.label, c.io_headroom?.note],
        ["Storage growth per day", fmtBytes((r.tables || []).reduce((a, t) => a + (t.bytes_per_day || 0), 0)), "MEASURED", "sum of measured rows/day × bytes/row per table (at the rates entered)"],
        ["Data size at full retention", fmtBytes(d.steady_state_bytes), "ESTIMATED", d.steady_state_frac != null ? `${pct(d.steady_state_frac)} of the disk incl. other files, Kafka and merge space` : ""],
        ["Days until the disk limit", d.days_until_limit != null ? num(d.days_until_limit) : "not reached at these rates", "ESTIMATED", `limit = ${100 - st.reserve}% of the disk`],
        ["Recommended expansion point", b.resource ? `${({ cpu: "CPU", disk_space: "disk space", disk_io: "disk I/O" })[b.resource]} at about ${num(b.multiplier, 1)}× today's workload` : "not estimable from current data", b.resource ? "ESTIMATED" : "UNKNOWN",
          b.resource ? "the first limit reached if every workload grows by the same factor" : b.note]];
      const g = groupRetention(r.tables || []);
      return [card("What can my existing server handle?", "the current hardware, with the measured workload mix", knobs, kv(capRows),
        el("p", { class: "muted small", text: "CPU clock speed, core count and network speed are not ingestion rates. Capacity comes from measured CPU cost per record, or from a benchmark on this hardware; when neither exists it stays unknown." })),
      card("Storage & retention", "measured bytes per row and daily volume per table; change retention to project", g, storageTable(r.tables || []))];
    }

    function groupRetention(tables) {
      const groups = [...new Set(tables.filter((t) => t.group !== "ClickHouse system logs" && t.group !== "Other").map((t) => t.group))];
      return el("div", { class: "row wrapgap" }, groups.map((gname) => {
        const cur = st.retention[gname] || tables.find((t) => t.group === gname)?.ttl_days;
        const s = el("select", {}, [["", "current TTL"], ...[7, 14, 30, 60, 90, 180, 365].map((d) => [String(d), `${d} days`])].map(([v, t]) => el("option", { value: v, text: t, selected: String(st.retention[gname] || "") === v })));
        s.addEventListener("change", () => { if (s.value) st.retention[gname] = +s.value; else delete st.retention[gname]; recalc(); });
        return el("label", {}, `${gname} (now ${num(cur)} d) `, s);
      }), el("span", { class: "muted small", text: "Aggregated flow tables keep separate TTLs (1-minute 7 d, 5-minute 90 d, 1-hour 365 d by default): queryable history is longer than raw retention." }));
    }
    function storageTable(tables) {
      return el("div", { class: "wrap" }, el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["Table", "Group", "Size now", "Bytes/row", "Compression", "Per day", "Retention", "At full retention", "History so far"].map((h) => el("th", { text: h })))),
        el("tbody", {}, tables.slice(0, 30).map((t) => el("tr", {}, el("td", { text: `${t.db}.${t.table}` }), el("td", { text: t.group }), el("td", { text: fmtBytes(t.bytes) }),
          el("td", { text: num(t.bytes_per_row, 1) }), el("td", { text: t.compression ? `${num(t.compression, 1)}×` : "—" }),
          el("td", { text: t.bytes_per_day != null ? fmtBytes(t.bytes_per_day) : "unknown", title: `confidence ${t.per_day_confidence}` }),
          el("td", { text: t.retention_days ? `${num(t.retention_days)} d` : "no TTL" }), el("td", { text: fmtBytes(t.steady_state_bytes) }),
          el("td", { text: t.age_days != null ? `${num(t.age_days, 1)} d${t.per_day_confidence === "low" ? " (low confidence)" : ""}` : "—" }))))));
    }

    function newResults(r) {
      const s = r.suggested, sp = r.storage_plan, rq = r.requirements;
      const rng = (x, f = (v) => num(v)) => `${f(x.low)} – ${f(x.high)} (mid ${f(x.mid)})`;
      return [card("Suggested workload", "ranges from the answers above; replace them with measurements once data exists", kv([
        ["Average traffic", rng(s.throughput_avg_mbps, (v) => `${num(v)} Mb/s`), "SUGGESTED"], ["Flow records/s (average)", rng(s.flows), "SUGGESTED"],
        ["Flow records/s (busiest minute)", rng(s.flows_peak), "SUGGESTED"], ["Log events/s", rng(s.events), "SUGGESTED"], ["DNS events/s", rng(s.dns), "SUGGESTED"],
        s.zeek.high ? ["Zeek records/s", rng(s.zeek), "SUGGESTED"] : null]),
        el("h3", { text: "Assumptions" }), el("ul", { class: "small" }, [...s.assumptions, ...s.calibrated].map((x) => el("li", { text: x })))),
      card("Requirements", r.storage_basis, kv([
        ["Storage at the chosen retention", `${fmtBytes(sp.low.total)} – ${fmtBytes(sp.high.total)}`, "ESTIMATED",
          `raw flows ${fmtBytes(sp.low.raw_flows)}–${fmtBytes(sp.high.raw_flows)}, aggregated ${fmtBytes(sp.low.aggregated_flows)}–${fmtBytes(sp.high.aggregated_flows)}, events ${fmtBytes(sp.low.events)}–${fmtBytes(sp.high.events)}, DNS ${fmtBytes(sp.low.dns)}–${fmtBytes(sp.high.dns)}, ClickHouse logs ${fmtBytes(sp.low.system_logs)}–${fmtBytes(sp.high.system_logs)}; add ≥15% free space`],
        ["CPU", rq.cpu.value ? `${num(rq.cpu.value[0], 1)} – ${num(rq.cpu.value[1], 1)} vCPU` : "unknown", rq.cpu.label, rq.cpu.note],
        ["Memory", rq.ram.value ? `reference: ${fmtBytes(rq.ram.value)} used by ClickHouse here` : "unknown", rq.ram.label, rq.ram.note]]),
        el("p", { class: "muted small", text: "Storage uses the low and high ends of the ranges. CPU and memory are only given from a benchmark or measurements; see docs/hardware-sizing.md for measured reference points." }))];
    }

    // ---- environment, findings, calibration
    function envCard(ov) {
      const v = ov.environment, s = v.server;
      const rows = v.devices.map((d) => el("tr", {}, el("td", {}, el("a", { href: `/netmon/settings/devices/${encodeURIComponent(d.id)}/hardware`, text: d.name }), el("div", { class: "muted small", text: d.primary ? "site firewall" : "additional device" })),
        el("td", { text: [d.manufacturer, d.model].filter(Boolean).join(" ") || "unknown" }), el("td", { text: `${d.cpu_cores ?? "?"} cores · ${d.ram_bytes ? fmtBytes(d.ram_bytes) : "RAM ?"}` }),
        el("td", {}, d.cpu?.p95 != null ? `${num(d.cpu.p95)}% P95` : d.cpu?.avg != null ? `${num(d.cpu.avg)}%` : "unknown", " ", lab(d.cpu?.label)),
        el("td", { text: d.flows?.avg != null ? num(d.flows.avg) : "—" }), el("td", { text: d.events?.avg != null ? num(d.events.avg, 1) : "—" }),
        el("td", { class: "small", text: (d.sources || []).map(([l, s2]) => `${s2 || "?"} (${l})`).join(", ") || "no hardware data yet" })));
      return card("Monitoring environment", v.note,
        kv([["m0nitor server", `${s.cpus} vCPU · ${fmtBytes(s.ram)} · ${fmtBytes(s.disk)} ${s.disk_type || ""}`, "MEASURED"],
          ["Central load", `CPU ${pct(s.cpu_p95)} P95 · RAM ${pct(s.mem_p95)} P95`, "MEASURED"],
          ["Total ingestion", `${num(v.totals.flows_avg)} flow records/s avg (${num(v.totals.flows_p95)} P95) · ${num(v.totals.events_avg, 1)} log events/s avg (${num(v.totals.events_p95, 1)} P95)`, "MEASURED"],
          ["First likely bottleneck", s.bottleneck?.resource ? `${s.bottleneck.resource.replace("_", " ")} at ~${num(s.bottleneck.multiplier, 1)}× today's workload` : "not estimable yet", s.bottleneck?.resource ? "ESTIMATED" : "UNKNOWN"]]),
        el("div", { class: "wrap" }, el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["Device", "Hardware", "Resources", "CPU", "Flows/s", "Events/s", "Data sources"].map((h) => el("th", { text: h })))), el("tbody", {}, rows))));
    }
    function findingsCard(ov) {
      return card("Forecasts and recommendations", "only statements backed by measurements or documented calculations",
        ov.forecasts.length ? el("ul", { class: "findings" }, ov.forecasts.map((f) => el("li", { class: f.level }, lab(f.label), " ", f.text, el("div", { class: "muted small", text: f.basis })))) : el("p", { class: "muted", text: "Nothing to report." }),
        ov.benchmarks.length ? el("p", { class: "small" }, `Benchmark results on file: ${ov.benchmarks.map((b) => b.id).join(", ")}. `, el("a", { href: "https://github.com/agit8or1/m0nitor/blob/main/docs/performance-benchmarks.md", text: "How they were measured" })) :
          el("p", { class: "muted small", text: "No benchmark results on this server. Capacity estimates without a measurable CPU model stay unknown; bench/bench.py measures this hardware in an isolated stack (docs/performance-benchmarks.md)." }));
    }
    function calibCard(ov) {
      const c = ov.calibration, o = ov.observe, h = c.history || [];
      const hours = o.flows.observed_hours || 0;
      const msg = o.flows.label !== "MEASURED" ? "No measurements yet: estimates use the generic assumption model."
        : hours < 6 ? `Low confidence — only ${num(hours, 1)} hours of monitoring data available.`
          : `Capacity estimate calibrated using ${hours >= 48 ? num(hours / 24, 1) + " days" : num(hours, 1) + " hours"} of actual measurements (${o.flows.confidence} confidence: ${o.flows.confidence_reason}).`;
      const r = c.ratios || {};
      return card("Calibration", "local, deployment-specific; global profiles are never changed by one installation", el("p", { text: msg }),
        kv([["Flow records per Mb/s", r.flows_per_mbps != null ? num(r.flows_per_mbps, 1) : "not enough data", r.flows_per_mbps != null ? "MEASURED" : "UNKNOWN", "used to calibrate 'Plan a new installation'"],
          ["Log events/s per firewall", r.logs_per_fw != null ? num(r.logs_per_fw, 1) : "not enough data", r.logs_per_fw != null ? "MEASURED" : "UNKNOWN", ""]]),
        h.length ? el("div", { class: "wrap" }, el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["When", "Metric", "Predicted", "Actual", "Difference", "Confidence"].map((x) => el("th", { text: x })))),
          el("tbody", {}, h.slice(0, 20).map((x) => el("tr", {}, el("td", { text: fmtTime(x.ts, true) }), el("td", { text: x.metric }), el("td", { text: x.predicted != null ? num(x.predicted, 1) : "—" }),
            el("td", { text: num(x.actual, 1) }), el("td", { text: x.predicted ? `${num(100 * (x.actual - x.predicted) / x.predicted)}%` : "—" }), el("td", { text: x.confidence || "" }))))))
          : el("p", { class: "muted small", text: "Calibration history starts one day after this version is installed (one record per day: yesterday's prediction vs today's measurement)." }));
    }
    async function save() {
      try { await post("/netmon/api/capacity/plan", { mode: st.mode, answers: st.answers, inputs: st.inputs, labels: st.labels, retention: st.retention, headroom: st.headroom, reserve: st.reserve,
        suggested: st.calc?.suggested ? { flows: st.calc.suggested.flows, events: st.calc.suggested.events } : null }); alert("Plan saved."); }
      catch (e) { alert(`Not saved: ${e.message}`); }
    }
    body.addEventListener("click", (ev) => { if (ev.target.textContent === "Recalculate now") load(true); });
  }

  // =================================================================== resources
  function resources() {
    let range = "24h";
    $("resrange").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { range = b.dataset.r; $("resrange").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); draw(); }));
    draw();
    async function draw() {
      const box = $("rescharts"); box.replaceChildren(el("p", { class: "muted", text: "Loading…" }));
      try {
        const d = await NM.get(`/netmon/api/capacity/series?range=${range}`);
        const last = (k) => { for (let i = d.points.length - 1; i >= 0; i--) if (d.points[i][k] != null) return d.points[i][k]; return null; };
        const kpi = (k, v, sub, cls = "") => el("div", { class: `kpi ${cls}` }, el("div", { class: "k", text: k }), el("div", { class: `v ${v == null ? "na" : ""}`, text: v ?? "unknown" }), el("div", { class: "s muted small", text: sub || "" }));
        const cpu = last("cpu"), mem = last("mem"), fs = last("fs_frac");
        $("reskpis").replaceChildren(kpi("CPU now", cpu != null ? pct(cpu) : null, "host, all vCPUs", cpu > 0.8 ? "bad" : cpu > 0.6 ? "warn" : ""),
          kpi("Memory in use", mem != null ? pct(mem) : null, "host", mem > 0.9 ? "bad" : ""), kpi("Disk used", fs != null ? pct(fs) : null, "ClickHouse data filesystem", fs > 0.85 ? "bad" : fs > 0.7 ? "warn" : ""),
          kpi("Flow records/s", last("flows") != null ? num(last("flows")) : null, `last ${d.step / 60}-min bucket`), kpi("Log events/s", last("events") != null ? num(last("events"), 1) : null, "stored"),
          kpi("Flow queue lag", d.kafka_lag.value != null ? num(d.kafka_lag.value) : null, "Kafka messages behind", d.kafka_lag.value > 100000 ? "bad" : ""));
        box.replaceChildren();
        const chart = (title, series, fmt, note) => { const c = el("div", { class: "chart" }); box.append(card(title, note, c)); requestAnimationFrame(() => NM.lineChart(c, d.points, series, { fmt, height: 220 })); };
        chart("CPU and memory", [{ key: "cpu", cls: "in", label: "CPU" }, { key: "mem", cls: "out", label: "Memory" }], (v) => pct(v), "host-wide; ClickHouse asynchronous_metric_log");
        chart("Flows and log events per second", [{ key: "flows", cls: "in", label: "Flow records/s" }, { key: "events", cls: "out", label: "Log events/s" }], (v) => num(v), "by time received; gaps = no data");
        chart("Disk busy time", [{ key: "io_util", cls: "in", label: "Busy" }], (v) => pct(v), `device ${d.device || "unknown"}; 100% = always busy (understates the limit of flash and virtual disks)`);
        chart("Disk throughput", [{ key: "write_Bps", cls: "in", label: "Write" }, { key: "read_Bps", cls: "out", label: "Read" }], (v) => fmtBytes(v) + "/s", "");
        chart("Disk latency and query latency", [{ key: "io_latency_ms", cls: "in", label: "I/O ms" }, { key: "q_p95_ms", cls: "out", label: "Query P95 ms" }], (v) => `${num(v, 1)} ms`, "ClickHouse SELECT queries (P95 per bucket)");
        chart("Data filesystem used", [{ key: "fs_frac", cls: "in", label: "Used" }], (v) => pct(v), "includes everything on the filesystem, not only monitoring data");
        const devs = Object.entries(d.devices);
        box.append(card("Firewall and device resources", "SNMP samples; CPU from the device's agent may not include dataplane/ASIC load",
          devs.length ? el("div", {}, devs.map(([id, x]) => { const c = el("div", { class: "chart" });
            requestAnimationFrame(() => NM.lineChart(c, x.points, [{ key: "cpu", cls: "in", label: "CPU %" }, { key: "mem", cls: "out", label: "Memory %" }], { fmt: (v) => `${num(v)}%`, height: 180 }));
            return el("div", {}, el("h3", {}, el("a", { href: `/netmon/settings/devices/${encodeURIComponent(id)}/hardware`, text: x.name })), c); }))
            : el("p", { class: "muted", text: "No device resource samples yet: configure SNMP on a device (history starts with this version)." })));
      } catch (e) { errBox(box, e); }
    }
  }

  // =================================================================== device
  async function device() {
    const did = root.dataset.device, box = $("hwbody");
    try {
      const d = await NM.get(`/netmon/api/capacity/device/${encodeURIComponent(did)}`);
      const hw = d.hardware, names = Object.fromEntries(d.manual_fields.map(([k, l]) => [k, l]));
      const show = (k, v) => k === "ram_bytes" || k === "storage_bytes" ? fmtBytes(v) : k === "if_list" ? `${v.length} interfaces` : Array.isArray(v) ? v.join(", ") : String(v);
      const order = ["manufacturer", "model", "sys_descr", "agent", "cpu_model", "cpu_cores", "ram_bytes", "cpu_pct", "mem_pct", "storage_bytes", "storage_used_pct", "interfaces", "if_speed_mbps", "uptime",
        "sessions", "sessions_max", "session_util_pct", ...Object.keys(hw)];
      const seen = new Set();
      const rows = order.filter((k) => hw[k] && !seen.has(k) && seen.add(k)).map((k) => { const f = hw[k];
        return el("tr", {}, el("th", { text: names[k] || k.replaceAll("_", " ") }), el("td", { text: show(k, f.value) }), el("td", {}, lab(f.label)),
          el("td", { class: "small", text: f.source }), el("td", { class: "small", text: f.ts ? ago(Date.now() / 1000 - f.ts) : "" }),
          el("td", { class: "small muted", text: f.manual && f.auto ? `discovered: ${show(k, f.auto.value)}` : "" })); });
      const missing = d.manual_fields.filter(([k]) => !hw[k]).map(([, l]) => l);
      const steps = d.discovery?.steps || [];
      const fl = d.flows || {}, ev = d.events || {};
      const bw = (x) => !x ? "unknown" : x.low == null ? "unknown" : x.low === x.high ? fmtBps(x.low) : `${fmtBps(x.low)} – ${fmtBps(x.high)}`;
      const cap = kv([["CPU", d.cpu?.p95 != null ? `${num(d.cpu.avg)}% avg · ${num(d.cpu.p95)}% P95 · ${num(d.cpu.peak)}% peak (${num(d.cpu.hours, 1)} h of samples)` : d.cpu?.avg != null ? `${num(d.cpu.avg)}%` : "unknown", d.cpu?.label, d.cpu?.note || d.cpu?.source],
        ["CPU trend", d.cpu_trend?.pct_points_per_day != null && d.cpu_trend.label === "MEASURED" ? `${num(d.cpu_trend.pct_points_per_day, 2)} points/day over ${num(d.cpu_trend.days, 1)} days` : "unknown", d.cpu_trend?.label || "UNKNOWN", d.cpu_trend?.note],
        ["CPU headroom", d.cpu_headroom ? `${num(d.cpu_headroom.value)} points below 80% at P95` : "unknown", d.cpu_headroom?.label || "UNKNOWN", d.cpu_headroom?.note],
        ["Memory", d.mem?.p95 != null ? `${num(d.mem.avg)}% avg · ${num(d.mem.p95)}% P95` : "unknown", d.mem?.label || "UNKNOWN", ""],
        ["Flow export workload", stat(fl, (x) => num(x)), fl.label, "records/s from this exporter"],
        ["Flow export bandwidth", bw(d.export_flow_bw), d.export_flow_bw?.label || "UNKNOWN", d.export_flow_bw?.basis],
        ["Syslog workload", stat(ev, (x) => num(x, 1)), ev.label, "stored events/s from this device"],
        ["Syslog export bandwidth", bw(d.export_syslog_bw), d.export_syslog_bw?.label || "UNKNOWN", d.export_syslog_bw?.basis],
        ["Export cost on the firewall CPU", d.cpu_model?.valid ? `${num(d.cpu_model.per_flow * 100 * 1000, 2)} CPU points per 1,000 records/s` : "insufficient information", d.cpu_model?.valid ? "ESTIMATED" : "UNKNOWN", d.cpu_model?.reason]]);
      const imp = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["Change", "Extra records/s", "Extra export bandwidth", "Firewall CPU", "Firewall RAM", "Notes"].map((h) => el("th", { text: h })))),
        el("tbody", {}, d.impacts.map((x) => el("tr", {}, el("td", { text: x.feature }), el("td", { text: x.records ? `${num(x.records[0], 1)} – ${num(x.records[1], 1)}` : "unknown" }),
          el("td", { text: x.bandwidth_bps ? `${fmtBps(x.bandwidth_bps[0])} – ${fmtBps(x.bandwidth_bps[1])}` : "unknown" }),
          el("td", {}, x.cpu_pct ? `${num(x.cpu_pct[0], 2)} – ${num(x.cpu_pct[1], 2)} points ` : "unknown ", lab(x.cpu_label)), el("td", { class: "small", text: x.ram }), el("td", { class: "small", text: x.note })))));
      const prof = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ["Profile", "What it collects", "Records/s", "Events/s", "Firewall export", "Firewall CPU", "Firewall RAM"].map((h) => el("th", { text: h })))),
        el("tbody", {}, d.profiles.map((p) => el("tr", {}, el("td", {}, el("b", { text: p.profile }), " ", lab(p.label)), el("td", { class: "small", text: p.description }),
          el("td", { text: p.flows ? `${num(p.flows[0])} – ${num(p.flows[1])}` : "unknown" }), el("td", { text: p.events ? `${num(p.events[0], 1)} – ${num(p.events[1], 1)}` : "unknown" }),
          el("td", { text: p.fw_export_bps ? `${fmtBps(p.fw_export_bps[0])} – ${fmtBps(p.fw_export_bps[1])}` : "unknown" }),
          el("td", { class: "small", text: p.fw_cpu ? (p.fw_cpu[0] === "ESTIMATED" ? `${num(p.fw_cpu[1][0], 2)}–${num(p.fw_cpu[1][1], 2)} points` : p.fw_cpu[1]) : "unknown" }),
          el("td", { class: "small", text: p.fw_ram ? p.fw_ram[1] : "unknown" })))));
      const form = admin ? (() => { const f = el("form", { method: "post", action: `/netmon/settings/devices/${encodeURIComponent(did)}/hardware/manual`, class: "grid-form" }, el("input", { type: "hidden", name: "csrf", value: csrf }));
        for (const [k, l, kind] of d.manual_fields) { const cur = hw[k]?.manual?.value;
          const input = kind.startsWith("select:") ? el("select", { name: k }, kind.slice(7).split(",").map((o) => el("option", { value: o, text: o, selected: cur === o })))
            : el("input", { name: k, type: kind === "text" ? "text" : "number", step: "any", min: 0, value: cur == null ? "" : kind === "gb" ? +(cur / 1024 ** 3).toFixed(1) : cur, placeholder: hw[k]?.auto ? `discovered: ${show(k, hw[k].auto.value)}` : "optional" });
          f.append(el("label", {}, l, input)); }
        f.append(el("div", { class: "row" }, el("button", { text: "Save manual values" }), el("span", { class: "muted small", text: "All fields are optional. Empty = use the discovered value or unknown." })));
        return el("details", { open: missing.length > 6 }, el("summary", { text: `Manual values${missing.length ? ` (${missing.length} fields not discovered)` : ""}` }), f); })() : null;
      box.replaceChildren(
        d.snmp.configured ? (d.snmp.version !== "v3" ? el("div", { class: "banner warn", text: "SNMPv2c: the community travels in clear text. Use SNMPv3 authPriv where the device supports it." }) : null)
          : el("div", { class: "banner", text: "SNMP is not configured for this device: discovery cannot read anything. Enter values manually below, or add SNMP (v3 recommended) in the device settings." }),
        el("h3", { text: "Hardware" }), rows.length ? el("div", { class: "wrap" }, el("table", { class: "tbl" }, el("tbody", {}, rows))) : el("p", { class: "muted", text: "Nothing known yet." }),
        steps.length ? el("details", {}, el("summary", { text: `Last discovery: ${steps.filter((s) => s[1]).length} of ${steps.length} steps answered${d.discovery?.ts ? ", " + ago(Date.now() / 1000 - d.discovery.ts) : ""}` }),
          el("ul", { class: "small" }, steps.map(([w, ok, det]) => el("li", {}, el("span", { class: `sev s-${ok ? "good" : "warning"}`, text: ok ? "✓" : "✕" }), ` ${w}${det ? " — " + det : ""}`)))) : null,
        form, el("h3", { text: "How much monitoring can this firewall handle?" }), cap,
        el("h3", { text: "Impact of enabling or changing telemetry" }), el("div", { class: "wrap" }, imp),
        el("p", { class: "muted small", text: "Bandwidth is computed from measured rates and record sizes. Firewall CPU and RAM overhead is shown only when measured on this device; otherwise it is insufficient information, never a guessed number." }),
        el("h3", { text: "Monitoring profiles" }), el("div", { class: "wrap" }, prof),
        el("p", { class: "muted small", text: "Profiles are suggestions. m0nitor never changes firewall configuration or disables security features automatically." }));
    } catch (e) { errBox(box, e); }
  }
})();
