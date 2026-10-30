// Shared UI: scope (URL-backed), toolbar, formatting, charts, tables.
// Telemetry strings are inserted with textContent only.
"use strict";
const NM = (() => {
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  };
  const $ = (id) => document.getElementById(id);

  // ---- units: bits for rates, bytes for volume (decimal SI) ----
  const unit = (v, units) => { let i = 0; v = +v || 0; while (Math.abs(v) >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return `${Math.abs(v) >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(Math.abs(v) >= 10 ? 1 : 2)} ${units[i]}`; };
  const fmtBytes = (b) => unit(b, ["B", "KB", "MB", "GB", "TB", "PB"]);
  const fmtBps = (b) => b == null ? "—" : unit(b, ["bps", "kbps", "Mbps", "Gbps", "Tbps"]);
  const fmtNum = (n) => (+n || 0).toLocaleString();
  const ago = (s) => s == null ? "never" : s < 90 ? `${Math.round(s)} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${(s / 3600).toFixed(1)} h ago` : `${Math.round(s / 86400)} d ago`;
  const tz = (() => { const o = -new Date().getTimezoneOffset(); const h = Math.floor(Math.abs(o) / 60), m = Math.abs(o) % 60;
    return `UTC${o >= 0 ? "+" : "−"}${h}${m ? ":" + String(m).padStart(2, "0") : ""}`; })();
  const fmtTime = (t, withDate) => { const d = new Date(t * 1000);
    return withDate ? d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const SEV = { critical: ["critical", "▲"], high: ["critical", "▲"], medium: ["serious", "◆"], low: ["warning", "●"], info: ["muted", "○"] };
  const sev = (s) => { const [c, i] = SEV[s] || ["muted", "○"]; return el("span", { class: `sev s-${c}`, text: `${i} ${s}` }); };

  // ---- scope ----
  const KEYS = ["site", "range", "from", "to", "cc", "host", "asn", "port", "rip"];
  const scope = {};
  function readScope() { const p = new URLSearchParams(location.search); for (const k of KEYS) scope[k] = p.get(k) || "";
    if (!scope.range) scope.range = "15m"; if (!scope.site) scope.site = "all"; }
  readScope();
  function qs(extra = {}) { const p = new URLSearchParams();
    for (const k of KEYS) { const v = k in extra ? extra[k] : scope[k]; if (v && !(k === "site" && v === "all")) p.set(k, v); }
    for (const [k, v] of Object.entries(extra)) if (!KEYS.includes(k) && v !== "" && v != null) p.set(k, v);
    return p.toString(); }
  const listeners = [];
  function setScope(ch) { Object.assign(scope, ch); if (scope.range !== "custom") { scope.from = ""; scope.to = ""; }
    history.replaceState(null, "", location.pathname + (qs() ? "?" + qs() : "")); syncToolbar(); keepLinks(); listeners.forEach((f) => f(scope)); }
  const onScope = (f) => listeners.push(f);
  const href = (path, extra = {}) => { const q = qs(extra); return path + (q ? "?" + q : ""); };
  function keepLinks() { document.querySelectorAll("a[data-keep]").forEach((a) => {
    const u = new URL(a.getAttribute("href"), location.origin); const base = new URLSearchParams(u.search);
    const p = new URLSearchParams(qs()); for (const [k, v] of base) if (!p.has(k)) p.set(k, v);
    a.setAttribute("href", u.pathname + (p.toString() ? "?" + p : "")); }); }

  // ---- live / pause ----
  let paused = false; try { paused = localStorage.getItem("nm.paused") === "1"; } catch (_) {}
  const timers = [];
  function every(fn, ms) { timers.push(setInterval(() => { if (!paused && !document.hidden) fn(); }, ms)); }

  function syncToolbar() {
    const site = $("site"); if (site) site.value = scope.site || "all";
    const rg = $("range"); if (rg) rg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.range === scope.range));
    const cu = $("custom"); if (cu) cu.hidden = scope.range !== "custom";
    const lv = $("live"); if (lv) { lv.textContent = paused ? "▶ Resume live" : "❚❚ Pause"; lv.setAttribute("aria-pressed", String(!paused)); lv.classList.toggle("paused", paused); }
    const chips = $("chips"); if (chips) {
      chips.replaceChildren();
      const lab = { cc: "Country", host: "Server", asn: "AS", port: "Port", rip: "Remote IP" };
      for (const k of ["cc", "host", "asn", "port", "rip"]) if (scope[k] && !(document.body.dataset.fixed || "").split(",").includes(k)) {
        const b = el("button", { class: "chip", title: "Remove filter" }, `${lab[k]}: ${scope[k]}`, el("span", { "aria-hidden": "true", text: " ×" }));
        b.addEventListener("click", () => setScope({ [k]: "" })); chips.append(b);
      }
      if (chips.children.length) chips.prepend(el("span", { class: "muted small", text: "Filtered:" }));
    }
  }
  const toLocalInput = (t) => { const d = new Date(t * 1000 - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };
  function bindToolbar() {
    const site = $("site"); if (site) site.addEventListener("change", () => setScope({ site: site.value }));
    const rg = $("range"); if (rg) rg.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.range === "custom") { scope.range = "custom"; const now = Date.now() / 1000;
        $("from").value = toLocalInput(+scope.from || now - 3600); $("to").value = toLocalInput(+scope.to || now); syncToolbar(); return; }
      setScope({ range: b.dataset.range }); });
    const ap = $("apply"); if (ap) ap.addEventListener("click", () => {
      const f = Date.parse($("from").value) / 1000, t = Date.parse($("to").value) / 1000;
      if (!(f < t)) { alertBox("Custom range: end must be after start"); return; }
      setScope({ range: "custom", from: String(Math.floor(f)), to: String(Math.floor(t)) }); });
    if (scope.range === "custom" && $("from")) { $("from").value = toLocalInput(+scope.from); $("to").value = toLocalInput(+scope.to); }
    const lv = $("live"); if (lv) lv.addEventListener("click", () => { paused = !paused; try { localStorage.setItem("nm.paused", paused ? "1" : "0"); } catch (_) {}
      syncToolbar(); if (!paused) listeners.forEach((f) => f(scope)); });
    syncToolbar(); keepLinks();
  }
  function alertBox(msg) { const c = $("chips"); if (c) { c.replaceChildren(el("span", { class: "err", text: msg })); } }

  // ---- data ----
  async function get(url) {
    const r = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (r.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); throw new Error("login required"); }
    let j; try { j = await r.json(); } catch (_) { throw new Error(`HTTP ${r.status}`); }
    if (!r.ok || j.ok === false) throw new Error(j.error || j.detail || r.statusText);
    return j;
  }
  function state(node, kind, msg) { node.replaceChildren(el("div", { class: `state ${kind}`, text: msg })); }

  // ---- freshness pill ----
  let live = null; const liveL = [];
  async function pollLive() {
    const pill = $("fresh"); if (!pill) return;
    try {
      live = await get("/netmon/api/live");
      const age = live.collection.age, last = live.collection.last;
      const [cls, icon, txt] = age == null ? ["critical", "✕", "No flow data"] : age < 120 ? ["good", "●", paused ? "Paused" : "Live"] : age < 600 ? ["warning", "◐", "Delayed"] : ["critical", "✕", "Stale"];
      pill.replaceChildren(el("span", { class: `sev s-${cls}`, text: `${icon} ${txt}` }), " last data ",
        el("b", { text: last ? fmtTime(last) : "—" }), el("span", { class: "muted", text: ` (${ago(age)})` }));
      pill.title = `Newest flow record received ${last ? new Date(last * 1000).toString() : "never"}. Times shown in ${tz}.`;
      liveL.forEach((f) => f(live));
    } catch (e) { pill.replaceChildren(el("span", { class: "sev s-critical", text: "✕ Telemetry error" }), " ", e.message.slice(0, 80)); }
  }

  // ---- tables ----
  function table(node, cols, rows, { empty = "No data for this scope", onRow, cls = "" } = {}) {
    node.replaceChildren();
    if (!rows || !rows.length) { node.append(el("div", { class: "state empty", text: empty })); return; }
    const t = el("table", { class: `tbl ${cls}` });
    t.append(el("thead", {}, el("tr", {}, cols.map((c) => el("th", { class: c.cls || "", text: c.label })))));
    const tb = el("tbody");
    for (const r of rows) { const tr = el("tr", {}, cols.map((c) => { const v = c.get(r); return el("td", { class: c.cls || "" }, v == null ? "—" : v); }));
      if (onRow) onRow(tr, r); tb.append(tr); }
    t.append(tb); node.append(el("div", { class: "wrap" }, t));
  }
  function rank(node, rows, { label, sub, link, inKey = "in_b", outKey = "out_b", value, empty } = {}) {
    node.replaceChildren();
    if (!rows || !rows.length) { node.append(el("div", { class: "state empty", text: empty || "No traffic in this scope" })); return; }
    const max = Math.max(...rows.map((r) => (+r[inKey] || 0) + (+r[outKey] || 0)), 1);
    const t = el("table", { class: "rank" });
    for (const r of rows) {
      const i = +r[inKey] || 0, o = +r[outKey] || 0;
      const lab = link ? el("a", { href: link(r), text: label(r), title: label(r) }) : el("span", { text: label(r), title: label(r) });
      const bar = el("div", { class: "bar", title: `in ${fmtBytes(i)} · out ${fmtBytes(o)}` });
      if (i) bar.append(el("span", { class: "i", style: `width:${(100 * i / max).toFixed(2)}%` }));
      if (o) bar.append(el("span", { class: "o", style: `width:${(100 * o / max).toFixed(2)}%` }));
      t.append(el("tr", {}, el("td", { class: "lbl" }, el("div", {}, lab), sub ? el("div", { class: "sub", text: sub(r), title: sub(r) }) : null),
        el("td", { class: "barcell" }, bar), el("td", { class: "num", text: value ? value(r) : fmtBytes(i + o) })));
    }
    node.append(t);
  }
  const legendInOut = (node, a = "Inbound", b = "Outbound") => node.replaceChildren(
    el("span", { class: "item" }, el("span", { class: "sw", style: "background:var(--in)" }), a),
    el("span", { class: "item" }, el("span", { class: "sw", style: "background:var(--out)" }), b));
  function pager(node, page, per, total, go) {
    node.replaceChildren(); const pages = Math.max(1, Math.ceil(total / per)); if (pages <= 1) { node.append(el("span", { class: "muted small", text: `${fmtNum(total)} rows` })); return; }
    const prev = el("button", { disabled: page <= 1 || null, text: "← Previous" }); prev.addEventListener("click", () => go(page - 1));
    const next = el("button", { disabled: page >= pages || null, text: "Next →" }); next.addEventListener("click", () => go(page + 1));
    node.append(prev, el("span", { class: "muted small", text: ` page ${page} of ${pages} · ${fmtNum(total)} rows ` }), next);
  }

  // ---- line chart (one y-axis, bits/s). null values are gaps. ----
  function lineChart(node, points, series, { unavailableBefore, height, refs = [] } = {}) {
    node.replaceChildren();
    const W = node.clientWidth || 800, H = height || node.clientHeight || 260, m = { t: 14, r: 86, b: 26, l: 70 };
    const svg = d3.select(node).append("svg").attr("viewBox", `0 0 ${W} ${H}`).attr("role", "img").attr("aria-label", series.map((s) => s.label).join(" and ") + " over time");
    if (!points.length) return;
    const x = d3.scaleTime().domain([new Date(points[0].t * 1000), new Date(points[points.length - 1].t * 1000)]).range([m.l, W - m.r]);
    const vals = points.flatMap((p) => series.map((s) => p[s.key])).filter((v) => v != null);
    // a capacity far above the data would flatten it: only scale to refs within 3x of the peak, flag the rest
    const vmax = d3.max(vals) || 1, inScale = refs.filter((r) => r.value <= vmax * 3), offScale = refs.filter((r) => r.value > vmax * 3);
    const y = d3.scaleLinear().domain([0, Math.max(vmax, ...inScale.map((r) => r.value)) * 1.12]).nice().range([H - m.b, m.t]);
    if (unavailableBefore && unavailableBefore > points[0].t) {
      const x1 = Math.min(x(new Date(unavailableBefore * 1000)), W - m.r);
      svg.append("rect").attr("class", "unavail").attr("x", m.l).attr("y", m.t).attr("width", Math.max(0, x1 - m.l)).attr("height", H - m.t - m.b);
      if (x1 - m.l > 90) svg.append("text").attr("class", "unavail-t").attr("x", (m.l + x1) / 2).attr("y", (H - m.b + m.t) / 2).attr("text-anchor", "middle").text("before collection started");
    }
    svg.append("g").selectAll("line").data(y.ticks(4)).join("line").attr("class", "gridline").attr("x1", m.l).attr("x2", W - m.r).attr("y1", y).attr("y2", y);
    svg.append("g").attr("class", "axis").attr("transform", `translate(${m.l},0)`).call(d3.axisLeft(y).ticks(4).tickFormat(fmtBps).tickSize(0).tickPadding(8)).call((g) => g.select(".domain").remove());
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b})`).call(d3.axisBottom(x).ticks(Math.max(2, Math.floor(W / 120))).tickSizeOuter(0));
    // contracted capacity: dashed reference line, labelled at the right edge
    for (const r of inScale) svg.append("line").attr("class", `capline ${r.cls || ""}`).attr("x1", m.l).attr("x2", W - m.r).attr("y1", y(r.value)).attr("y2", y(r.value));
    if (offScale.length) svg.append("text").attr("class", "endlabel cap").attr("x", W - m.r - 4).attr("y", m.t + 10).attr("text-anchor", "end")
      .text(`${offScale.map((r) => `${r.label} ${fmtBps(r.value)}`).join(" · ")} — above this scale (${(100 * vmax / Math.min(...offScale.map((r) => r.value))).toFixed(1)}% peak use)`);
    if (!vals.length) { svg.append("text").attr("class", "unavail-t").attr("x", W / 2).attr("y", H / 2).attr("text-anchor", "middle").text("No data in this window"); return; }
    const ends = inScale.map((r) => ({ y: y(r.value) + 4, label: r.label, cls: "cap" }));
    for (const s of series) {
      const line = d3.line().defined((p) => p[s.key] != null).x((p) => x(new Date(p.t * 1000))).y((p) => y(p[s.key]));
      svg.append("path").datum(points).attr("class", `line ${s.cls}${s.dash ? " dash" : ""}`).attr("d", line);
      // isolated points (gaps on both sides) as dots so they are not invisible
      svg.append("g").selectAll("circle").data(points.filter((p, i) => p[s.key] != null && (points[i - 1]?.[s.key] == null) && (points[i + 1]?.[s.key] == null)))
        .join("circle").attr("class", `dot ${s.cls}`).attr("r", 2.5).attr("cx", (p) => x(new Date(p.t * 1000))).attr("cy", (p) => y(p[s.key]));
      const last = [...points].reverse().find((p) => p[s.key] != null);
      if (last) ends.push({ y: y(last[s.key]) + 4, label: s.label });
    }
    // clamp to the plot first, then dodge upward from the bottom so labels never stack on each other
    ends.forEach((e) => { e.y = Math.min(e.y, H - m.b + 4); });
    ends.sort((a, b) => b.y - a.y);
    for (let i = 1; i < ends.length; i++) if (ends[i - 1].y - ends[i].y < 13) ends[i].y = ends[i - 1].y - 13;
    for (const e of ends) svg.append("text").attr("class", `endlabel ${e.cls || ""}`).attr("x", W - m.r + 6).attr("y", e.y).text(e.label);
    const tip = el("div", { class: "tip", hidden: true }); node.append(tip);
    const cross = svg.append("line").attr("class", "cross").attr("y1", m.t).attr("y2", H - m.b).style("display", "none");
    const dots = series.map((s) => svg.append("circle").attr("class", `dot ${s.cls}`).attr("r", 4).style("display", "none"));
    const bis = d3.bisector((p) => p.t * 1000).center;
    svg.append("rect").attr("x", m.l).attr("y", m.t).attr("width", W - m.l - m.r).attr("height", H - m.t - m.b).attr("fill", "transparent")
      .on("pointermove", (ev) => {
        const [mx] = d3.pointer(ev); const p = points[bis(points, x.invert(mx))]; if (!p) return;
        const px = x(new Date(p.t * 1000)); cross.attr("x1", px).attr("x2", px).style("display", null);
        series.forEach((s, i) => p[s.key] == null ? dots[i].style("display", "none") : dots[i].attr("cx", px).attr("cy", y(p[s.key])).style("display", null));
        tip.replaceChildren(el("div", { class: "t", text: `${fmtTime(p.t, true)} (${tz})` }),
          ...series.map((s) => el("div", { class: "r" }, el("span", { class: "sw", style: `background:var(--${s.cls})` }), s.label, el("b", { text: p[s.key] == null ? "no data" : fmtBps(p[s.key]) }))));
        tip.hidden = false; const sx = node.clientWidth / W;
        let left = px * sx + 14; if (left + tip.offsetWidth > node.clientWidth) left = px * sx - tip.offsetWidth - 14;
        tip.style.left = `${left}px`; tip.style.top = "6px";
      })
      .on("pointerleave", () => { tip.hidden = true; cross.style("display", "none"); dots.forEach((d) => d.style("display", "none")); });
  }

  // ---- shared panels ----
  function cards(node, items) {
    node.replaceChildren(...items.map((c) => el(c.href ? "a" : "div", { class: `kpi${c.href ? " link" : ""}${c.cls ? " " + c.cls : ""}`, href: c.href || null, title: c.tip || null },
      el("div", { class: "k" }, c.sw ? el("span", { class: "sw", style: `background:var(${c.sw})` }) : null, c.k),
      el("div", { class: "v" }, c.v), c.s ? el("div", { class: "s" }, c.s) : null, c.s2 ? el("div", { class: "s" }, c.s2) : null)));
  }
  // Utilization meter: one ratio against a limit. Fill = direction color (identity); state = icon + word.
  function utilState(pct) {
    if (pct == null) return null;
    return pct >= 90 ? ["critical", "✕", "Saturated"] : pct >= 70 ? ["warning", "▲", "High"] : ["good", "●", "Normal"];
  }
  function meterRow(label, cls, bps, peak, capMbps) {
    const cap = capMbps ? capMbps * 1e6 : null;
    const pct = cap && bps != null ? 100 * bps / cap : null, ppct = cap && peak != null ? 100 * peak / cap : null;
    const st = utilState(pct);
    const track = el("div", { class: "mtrack", role: "meter", "aria-label": `${label} utilization`,
      "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": pct == null ? "" : pct.toFixed(0) });
    if (pct != null) track.append(el("div", { class: `mfill ${cls}`, style: `width:${Math.min(100, pct).toFixed(1)}%` }));
    if (ppct != null) track.append(el("div", { class: "mpeak", style: `left:${Math.min(100, ppct).toFixed(1)}%`, title: `1 h peak ${fmtBps(peak)}` }));
    if (!cap && bps != null) track.classList.add("nocap");
    const pctTxt = pct == null ? "" : pct > 0 && pct < 0.1 ? "<0.1%" : `${pct.toFixed(pct < 10 ? 1 : 0)}%`;
    const val = bps == null ? "no data" : cap ? `${fmtBps(bps)} of ${fmtBps(cap)} · ${pctTxt}` : `${fmtBps(bps)} · capacity not set`;
    const row = el("div", { class: "mrow" }, el("span", { class: "mlab" }, el("span", { class: `sw`, style: `background:var(--${cls})` }), label), track,
      el("span", { class: "mval" }, val, st ? el("span", { class: `sev s-${st[0]}`, text: ` ${st[1]} ${st[2]}` }) : null));
    row.title = [`${label}: ${bps == null ? "no data" : fmtBps(bps)}`, cap ? `capacity ${fmtBps(cap)}` : "capacity not configured",
      peak != null ? `1 h peak ${fmtBps(peak)}${cap ? ` (${ppct.toFixed(0)}%)` : ""}` : ""].filter(Boolean).join(" · ");
    return row;
  }
  function meters(node, sites, { compact = false } = {}) {
    node.replaceChildren();
    if (!sites || !sites.length) { node.append(el("div", { class: "state empty", text: "No firewalls configured" })); return; }
    for (const s of sites) {
      node.append(el("div", { class: "meter" },
        compact ? null : el("div", { class: "mh" }, el("b", { text: s.name }), el("span", { class: "muted small", text: ` ${s.vendor === "pfsense" ? "pfSense" : "OPNsense"}` })),
        meterRow("Download", "in", s.in_bps, s.peak_in_bps, s.down_mbps),
        meterRow("Upload", "out", s.out_bps, s.peak_out_bps, s.up_mbps),
        el("div", { class: "note", text: s.source ? `${s.source}${s.down_mbps || s.up_mbps ? "" : " · set capacity in Settings → Firewalls"}` : "No interface counters or recent flows from this firewall" })));
    }
  }
  const DIRECTION = { inbound: "⬇ Inbound", outbound: "⬆ Outbound", internal: "↔ Internal", both: "⇅ Both directions", transit: "Transit" };
  function alertList(node, alerts, { limit = 10, empty = "No open findings" } = {}) {
    node.replaceChildren();
    if (!alerts.length) { node.append(el("div", { class: "state empty", text: empty })); return; }
    const groups = { security: "Security alerts", response: "Auto-response actions", health: "Monitoring health", info: "Informational changes" };
    for (const [g, title] of Object.entries(groups)) {
      const items = alerts.filter((a) => a.category === g).slice(0, limit); if (!items.length) continue;
      node.append(el("h3", { class: "grp", text: `${title} (${items.length})` }));
      const ul = el("ul", { class: "alist" });
      for (const a of items) ul.append(el("li", {}, sev(a.severity), el("div", {},
        a.direction ? el("span", { class: `dir dir-${a.direction}${a.direction_verified ? "" : " unverified"}`, title: a.direction_basis || "" },
          DIRECTION[a.direction] || a.direction, el("small", { text: a.direction_verified ? "✓ verified" : "? unverified" })) : null, " ",
        el("a", { href: `/netmon/alert/${a.id}`, text: a.title }),
        el("div", { class: "muted small", text: `${a.rule} · confidence ${a.confidence} · ${a.count}× · ${ago(Date.now() / 1000 - a.last_seen)}` }),
        a.next ? el("div", { class: "small next", text: `Next: ${a.next}` }) : null)));
      node.append(ul);
    }
  }
  function convTable(node, rows, opts = {}) {
    table(node, [
      { label: "Last seen", cls: "num", get: (r) => fmtTime(r.last, true) },
      { label: "Internal server", get: (r) => r.server_name && r.server_name !== r.server
          ? el("a", { href: href(`/netmon/servers/${r.server}`), text: r.server_name, title: r.server })
          : ipCell(r.server, "", href(`/netmon/servers/${r.server}`)) },
      { label: "Direction", get: (r) => el("span", { title: r.evidence, text: r.direction }) },
      { label: "Remote IP", get: (r) => ipCell(r.remote, r.remote_name) },
      { label: "Country", get: (r) => r.cc ? el("a", { href: href(`/netmon/countries/${r.cc}`), text: r.cc_name }) : "Unknown" },
      { label: "Organization", get: (r) => r.asname || (r.asn ? `AS${r.asn}` : "—") },
      { label: "Service", get: (r) => el("span", {}, r.service, el("div", { class: "sub", text: r.service_evidence })) },
      { label: "Bytes (remote→server)", cls: "num", get: (r) => fmtBytes(r.rx) },
      { label: "", get: (r) => { const d = el("details", { class: "tech" }, el("summary", { text: "details" }),
          el("pre", { text: JSON.stringify({ observation: "WAN inbound record (InIf=WAN → OutIf=LAN)", protocol: r.proto, service_port: r.svc_port, service_side: r.svc_side,
            server_ports: r.server_ports, remote_ports: r.remote_ports, flow_records: r.flows, packets: r.pkts, first_seen: new Date(r.first * 1000).toISOString(),
            last_seen: new Date(r.last * 1000).toISOString(), asn: r.asn, direction_evidence: r.evidence }, null, 1) })); return d; } },
    ], rows, { cls: "conv", ...opts });
  }
  // ---- name / label any address in place (✎) ----
  const meta = (n) => (document.querySelector(`meta[name="${n}"]`) || {}).content || "";
  const canName = () => ["analyst", "admin"].includes(meta("nm-role"));
  function ipCell(ip, name, link) {
    let btn = null;
    if (canName()) {
      btn = el("button", { class: "namebtn", type: "button", title: name ? `Rename ${ip}` : `Name ${ip}`, "aria-label": `Name ${ip}` }, "✎");
      btn.addEventListener("click", (ev) => { ev.preventDefault(); ev.stopPropagation(); namer(ip); });
    }
    return el("span", { class: "ipcell" }, el("a", { class: "mono", href: link || href("/netmon/connections", { rip: ip }), text: ip }), btn,
      el("div", { class: "sub ipname", "data-ip": ip, title: "your name for this address (Settings → Inventory)", text: name || "" }));
  }
  async function namer(ip, onSaved) {
    let d;
    try { d = await get(`/netmon/api/name?ip=${encodeURIComponent(ip)}`); } catch (e) { alert(e.message); return; }
    const dlg = el("dialog", { class: "namer" }), msg = el("p", { class: "muted small" });
    const inp = (n, v, ph, extra = {}) => el("input", { name: n, value: v || "", placeholder: ph, maxlength: n === "notes" ? 300 : 64, ...extra });
    const f = el("form", { method: "dialog", class: "stackform" },
      el("h2", { text: d.internal ? `Name server ${d.ip}` : `Label ${d.ip}` }),
      el("label", {}, "Name", inp("name", d.name, d.internal ? "server name" : "e.g. Office VPN, Backup provider", { autofocus: true })),
      el("label", {}, "Aliases", inp("aliases", (d.aliases || []).join(", "), "other names, comma-separated (e.g. ns1, cp.example.com)", { maxlength: 400 })),
      d.internal ? el("label", {}, "Role", inp("role", d.role, "web, mail, backup…")) : null,
      d.internal ? el("label", { class: "check" }, el("input", { type: "checkbox", name: "sensitive", value: "1", checked: d.sensitive }), " Sensitive — new outbound destinations raised one severity level") : null,
      el("label", {}, "Notes", inp("notes", d.notes, "optional")),
      d.can_edit ? null : el("p", { class: "warnline", text: `Naming ${d.internal ? "servers" : "external addresses"} requires the ${d.needs} role.` }),
      msg,
      el("div", { class: "row" }, el("button", { class: "primary", value: "save", disabled: !d.can_edit, text: "Save" }),
        d.name && d.can_edit ? el("button", { value: "clear", class: "ghost", text: "Remove name" }) : null,
        el("button", { value: "cancel", formnovalidate: true, text: "Cancel" })));
    f.addEventListener("submit", async (ev) => {
      const act = ev.submitter && ev.submitter.value;
      if (act === "cancel") return;
      ev.preventDefault();
      const fd = new FormData(f); fd.set("ip", d.ip); fd.set("csrf", meta("nm-csrf")); if (act === "clear") fd.set("clear", "1");
      try {
        const r = await fetch("/netmon/names", { method: "POST", body: fd, credentials: "same-origin", headers: { "x-nm-fetch": "1" } });
        const j = await r.json();
        if (!j.ok) { msg.textContent = j.error || j.detail || "Not saved"; msg.className = "warnline"; return; }
        document.querySelectorAll(`.ipname[data-ip="${CSS.escape(d.ip)}"]`).forEach((n) => { n.textContent = j.name; });
        dlg.close();
        if (onSaved) onSaved(j);
      } catch (e) { msg.textContent = e.message; msg.className = "warnline"; }
    });
    dlg.append(f); document.body.append(dlg);
    dlg.addEventListener("close", () => dlg.remove());
    dlg.showModal();
  }

  function scopeDesc(sc) { const n = $("scopedesc"); if (n && sc) n.textContent = `${sc.describe} · ${fmtTime(sc.start, true)} → ${fmtTime(sc.end, true)} (${tz})`; }

  document.addEventListener("DOMContentLoaded", () => { bindToolbar(); pollLive(); setInterval(pollLive, 10000); });
  return { el, $, fmtBytes, fmtBps, fmtNum, ago, fmtTime, tz, css, sev, scope, qs, href, setScope, onScope, every, get, state, table, rank,
    legendInOut, pager, lineChart, cards, alertList, meters, convTable, scopeDesc, ipCell, namer, onLive: (f) => liveL.push(f), live: () => live,
    isPaused: () => paused };
})();
