// World traffic map: country aggregation, directional arcs from the selected site(s).
"use strict";
const NMMap = (() => {
  const { el, fmtBytes, fmtBps, fmtNum } = NM;
  let topo = null, meta = null;
  async function assets() {
    if (!topo) [topo, meta] = await Promise.all([fetch("/netmon/static/countries-110m.json").then((r) => r.json()),
      fetch("/netmon/static/countries-meta.json").then((r) => r.json())]);
  }
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Natural Earth 110m draws some territories inside their parent's shape (France's includes French Guiana, Norway's
  // Svalbard). GeoIP data and the firewall's GeoIP aliases give them their own ISO codes, so those polygons are split
  // out by verified location (polygon centroid inside the territory's bounds), never by polygon order or names.
  const SPLIT = [
    { from: "FR", cc: "GF", inside: ([x, y]) => x > -55 && x < -51 && y > 1.5 && y < 6.5 },        // French Guiana
    { from: "NO", cc: "SJ", inside: ([, y]) => y > 74 },                                              // Svalbard (and Jan Mayen)
    { from: "RU", cc: "", label: "Crimea", inside: ([x, y]) => x > 32 && x < 37 && y > 44 && y < 46.5 }, // disputed: GeoIP decides per address
  ];
  // shapes the dataset gives no ISO code: Kosovo has GeoIP's user-assigned code XK; N. Cyprus and Somaliland have none
  // of their own (GeoIP attributes their addresses to CY/TR and SO), so they stay explicitly unknown
  const NOCODE = [{ cc: "XK", inside: ([x, y]) => x > 20 && x < 21.9 && y > 41.8 && y < 43.3 }];
  function territories(features) {
    for (const t of SPLIT) {
      const f = features.find((x) => x.properties.cc === t.from);
      if (!f || f.geometry.type !== "MultiPolygon") continue;
      const part = f.geometry.coordinates.filter((p) => t.inside(d3.geoCentroid({ type: "Polygon", coordinates: p })));
      if (!part.length || part.length === f.geometry.coordinates.length) continue;
      f.geometry.coordinates = f.geometry.coordinates.filter((p) => !part.includes(p));
      features.push({ type: "Feature", id: `split-${t.cc || t.label}`, properties: { cc: t.cc, label: t.label || "", name: t.label || t.cc },
        geometry: part.length > 1 ? { type: "MultiPolygon", coordinates: part } : { type: "Polygon", coordinates: part[0] } });
    }
    for (const f of features) if (!f.properties.cc && !f.properties.label) {
      const m = NOCODE.find((t) => t.inside(d3.geoCentroid(f)));
      if (m) f.properties.cc = m.cc; else f.properties.label = f.properties.name || "Unnamed territory";
    }
    return features;
  }

  // policyOnly: a map of the GeoIP block policy alone (texture per direction; no traffic arcs or finding markers)
  function create(node, { onSelect, policyOnly = false } = {}) {
    let svg, g, gC, gA, gL, gS, gM, path, proj, zoom, tip, features, last = null, size = [0, 0], pinned = false, kf = -1, tipFor = null, ptype = "mouse";
    const st = { dir: "both", shade: policyOnly ? "blocked" : "bytes" };
    // Built to the node's current size and rebuilt on resize: the projection fits the land (no Antarctica) so the map fills its panel.
    function build() {
      const W = Math.max(280, Math.round(node.clientWidth || 900)), H = Math.max(160, Math.round(node.clientHeight || W * 0.5));
      size = [W, H];
      if (svg) svg.remove();
      proj = d3.geoNaturalEarth1().fitExtent([[10, 10], [W - 10, H - 10]], { type: "FeatureCollection", features });
      path = d3.geoPath(proj);
      svg = d3.select(node).insert("svg", ":first-child").attr("viewBox", `0 0 ${W} ${H}`).attr("role", "application").attr("tabindex", 0)
        .attr("aria-label", `${policyOnly ? "World map of the GeoIP block policy" : "World map of observed traffic by country"}. Arrow keys move between countries, Enter opens one, Escape closes the details.`);
      svg.append("rect").attr("class", "sphere").attr("width", W).attr("height", H);
      // GeoIP-block textures: inbound 45°, outbound 135°, both crosshatched (texture, not a new hue)
      const defs = svg.append("defs");
      for (const [id, angles] of [["in", [45]], ["out", [135]], ["both", [45, 135]]]) {
        const pt = defs.append("pattern").attr("id", `nm-blk-${id}`).attr("patternUnits", "userSpaceOnUse").attr("width", 6).attr("height", 6);
        pt.append("rect").attr("width", 6).attr("height", 6).style("fill", "var(--blk-bg)");
        for (const a of angles) pt.append("path").attr("d", "M-1,3 H7").attr("transform", `rotate(${a} 3 3)`).style("stroke", "var(--blk-line)").style("stroke-width", 1.4);
      }
      // unknown / mixed policy: neutral dots, deliberately unlike the block hatching and the solid "not in policy" fill
      const pu = defs.append("pattern").attr("id", "nm-unk").attr("patternUnits", "userSpaceOnUse").attr("width", 5).attr("height", 5);
      pu.append("rect").attr("width", 5).attr("height", 5).style("fill", "var(--unk-bg)");
      pu.append("circle").attr("cx", 2.5).attr("cy", 2.5).attr("r", 0.9).style("fill", "var(--unk-dot)");
      g = svg.append("g");
      g.append("path").datum(d3.geoGraticule10()).attr("class", "graticule").attr("d", path);
      gC = g.append("g"); gA = g.append("g"); gL = g.append("g"); gS = g.append("g"); gM = g.append("g");
      gC.selectAll("path").data(features).join("path").attr("class", "country").attr("d", path).attr("fill", "var(--map-empty)")
        .on("pointerdown", (ev) => { ptype = ev.pointerType || "mouse"; })
        .on("pointermove", (ev, f) => { if (!pinned && ev.pointerType !== "touch") { tipFor = f; show(ev, countryTip(f)); } }).on("pointerleave", hide)
        .on("click", (ev, f) => {
          // touch: the first tap shows the details, a second tap on the same country opens it
          if (ptype === "touch" && tipFor !== f) { tipFor = f; show(ev, countryTip(f)); return; }
          unpin(); if (f.properties.cc && onSelect) onSelect(f.properties.cc); });
      svg.on("keydown", (ev) => {
        const order = keyOrder();
        if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(ev.key)) {
          ev.preventDefault(); kf = (kf + (ev.key === "ArrowRight" || ev.key === "ArrowDown" ? 1 : order.length - 1)) % order.length; focusFeature(order[kf]);
        } else if (ev.key === "Enter" && kf >= 0 && order[kf].properties.cc && onSelect) onSelect(order[kf].properties.cc);
      }).on("focus", () => { const order = keyOrder(); if (kf < 0) kf = 0; focusFeature(order[kf]); })
        .on("blur", () => { gC.selectAll("path").classed("kfocus", false); hide(); });
      zoom = d3.zoom().scaleExtent([1, 8]).translateExtent([[0, 0], [W, H]]).on("zoom", (ev) => g.attr("transform", ev.transform));
      svg.call(zoom).on("dblclick.zoom", null);
    }
    const fname = (f) => f.properties.cc ? cname(f.properties.cc) : f.properties.label;
    const keyOrder = () => features.slice().sort((a, b) => fname(a).localeCompare(fname(b)));
    function focusFeature(f) {
      gC.selectAll("path").classed("kfocus", (x) => x === f);
      const [x, y] = d3.zoomTransform(svg.node()).apply(path.centroid(f));
      tipFor = f; show({ at: [x, y] }, countryTip(f));
    }
    async function init() {
      await assets();
      const numToA2 = {}; for (const [a2, m] of Object.entries(meta)) if (m.n) numToA2[String(+m.n)] = a2;
      features = topojson.feature(topo, topo.objects.countries).features.filter((f) => f.id !== "010");
      for (const f of features) f.properties.cc = numToA2[String(+f.id)] || "";
      territories(features);
      tip = el("div", { class: "tip", hidden: true, role: "tooltip", "aria-live": "polite" }); node.append(tip);
      build();
      let rt; new ResizeObserver(() => { clearTimeout(rt); rt = setTimeout(() => {
        const W = Math.round(node.clientWidth), H = Math.round(node.clientHeight);
        if (W && H && (Math.abs(W - size[0]) > 2 || Math.abs(H - size[1]) > 2)) { build(); if (last) render(last); }
      }, 150); }).observe(node);
      document.addEventListener("pointerdown", (ev) => { if (pinned && !tip.contains(ev.target) && !ev.target.closest?.(".amark,.amark-hit")) unpin(); });
      document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") unpin(); });
    }
    const ready = init();

    const vol = (c, dir) => dir === "in" ? c.in_b : dir === "out" ? c.out_b : c.in_b + c.out_b;
    const nBlk = (cc) => { const b = last.blocks && last.blocks.countries && last.blocks.countries[cc]; if (!b) return 0;
      return st.dir === "in" ? b.in : st.dir === "out" ? b.out : b.in + b.out; };
    function val(c) { if (!c) return 0; if (st.shade === "blocks") return nBlk(c.cc); if (st.shade === "flows") return c.flows;
      if (st.shade === "alerts") { const a = last.alerts[c.cc] || {}; return (a.security || 0) * 10 + (a.info || 0); }
      return vol(c, st.dir); }
    const cname = (cc) => (meta[cc] && meta[cc].name) || (cc === "??" ? "Unknown location" : cc || "Unknown territory");
    const win = () => last.window || `${Math.round(last.span / 60)} min`;
    const secLine = (cc) => { const a = last.alerts[cc] || {}, n = a.security || 0, ep = new Set((a.items || []).flatMap((x) => x.endpoints)).size;
      return n ? `${n} open finding${n > 1 ? "s" : ""} name ${ep || "some"} endpoint${ep === 1 ? "" : "s"} here — not all traffic` : "No open findings"; };
    const row = (k, v) => el("div", { class: "r" }, k, el("b", { text: v }));
    // policy state of a country across the firewalls in scope: "in" | "out" | "both" | "" (not in block policy) |
    // "mixed" (firewalls differ) | "unknown" (no ISO code for the shape, or a firewall's policy is unreadable)
    const one = (i, o) => i && o ? "both" : i ? "in" : o ? "out" : "";
    const blk = (cc) => { if (!last.blocked && !last.policySites) return null; if (!cc) return "unknown";
      if (last.policySites && last.policySites.length) {
        if (last.policySites.some((p) => p.unknown)) return "unknown";
        const ks = new Set(last.policySites.map((p) => one(p.in.has(cc), p.out.has(cc))));
        return ks.size > 1 ? "mixed" : [...ks][0]; }
      return one(last.blocked.in.has(cc), last.blocked.out.has(cc)); };
    const POLICY = { both: "Configured block · inbound and outbound", in: "Configured block · inbound", out: "Configured block · outbound",
      "": "Not in block policy", mixed: "Mixed policy (firewalls differ)", unknown: "Unknown" };
    const blkRow = (cc) => { const k = blk(cc); return k === null ? null : row("GeoIP policy", POLICY[k]); };
    function scopeRow(cc) {
      const ps = last.policySites; if (!ps || !ps.length) return null;
      const parts = ps.map((p) => p.unknown ? `${p.name}: policy not readable` :
        `${p.name}: ${p.rules.length ? p.rules.map((r) => `${r.interface} rule ${r.sequence} (${r.side === "source" ? "inbound" : "outbound"})`).join(", ") : "no enabled GeoIP block rule"}`);
      return row("Policy scope", parts.join(" · "));
    }
    function blockRows(cc) {
      const B = last.blocks; if (!B) return [];
      if (!cc) return [row("Logged blocks", "not attributable to this shape (no country code of its own)")];
      if (B.state === "unavailable") return [el("div", { class: "tipwarn", text: "Blocked activity unavailable — connect firewall logs." })];
      if (B.state === "error") return [el("div", { class: "tipwarn", text: `Blocked activity unavailable: ${B.error}` })];
      const c = B.countries[cc], out = [];
      const zero = B.state === "ok" ? "0 logged blocks in this window" : "none logged in this window";
      out.push(row("Logged block events", c ? `⬇ ${fmtNum(c.in)} in · ⬆ ${fmtNum(c.out)} out` : zero));
      if (c && B.geo_rules && B.geo_rules.length) out.push(row("… by the GeoIP rule", `⬇ ${fmtNum(c.in_geo)} · ⬆ ${fmtNum(c.out_geo)}`));
      if (c) out.push(row("Logged blocked packet bytes", B.bytes_complete ? fmtBytes(c.in_bytes + c.out_bytes) : "Blocked volume unavailable"));
      out.push(row("Last logged block", c ? `${NM.fmtTime(c.last, true)} (${NM.ago(Date.now() / 1000 - c.last)})` : "—"));
      for (const v of B.coverage || []) if (v.state !== "ok") out.push(el("div", { class: "tipwarn", text: `${v.state === "stale" ? "⚠ stale · " : ""}${v.name}: ${v.note}` }));
      return out;
    }
    const winRow = () => last.scope ? row("Window", `${NM.fmtTime(last.scope.start, true)} → ${NM.fmtTime(last.scope.end, true)}`) : row("Window", win());
    const hint = () => el("div", { class: "muted small", text: last.clickHint || "Click to filter by this country" });
    const sw = (cls, t) => el("span", {}, el("span", { class: "sw", style: `background:var(--${cls})` }), ` ${t}`);

    function countryTip(f) {
      if (!last) return null;
      const cc = f.properties.cc, c = cc && last.byCc[cc];
      const title = el("div", { class: "t", text: cc ? `${cname(cc)} · ${cc}` : `${f.properties.label} — no separate GeoIP country` });
      if (!cc) return [title, row("GeoIP policy", POLICY.unknown),
        el("div", { class: "muted small", text: "GeoIP gives this area no code of its own: its addresses are counted under whichever country GeoIP assigns them." })];
      if (policyOnly || last.blocks) return [title, blkRow(cc), scopeRow(cc), winRow(),
        row("Observed traffic (NetFlow)", c ? `⬇ ${fmtBytes(c.in_b)} · ⬆ ${fmtBytes(c.out_b)}` : "none in this window"),
        ...blockRows(cc), !policyOnly && c ? row("Security", secLine(cc)) : null, hint()];
      const span = last.span;
      return [title, ...(c ? [
        row("Top organization", c.top_asname || (c.top_asn ? `AS${c.top_asn}` : "—")),
        row(sw("in", "Inbound"), `${fmtBytes(c.in_b)} · avg ${fmtBps(c.in_b * 8 / span)}`),
        row(sw("out", "Outbound"), `${fmtBytes(c.out_b)} · avg ${fmtBps(c.out_b * 8 / span)}`),
        row("Flows", fmtNum(c.flows)), row("Internal servers", fmtNum(c.servers)), row("Window", win()),
        row("Location", "country-level GeoIP (approximate)"), row("Security", secLine(cc)), blkRow(cc),
        hint()] : [blkRow(cc), el("div", { class: "muted small", text: "No observed traffic in this scope" })])];
    }
    function arcTip(a) {
      const c = last.byCc[a.cc], b = a.dir === "in" ? c.in_b : c.out_b;
      return [el("div", { class: "t", text: a.dir === "in" ? `${cname(a.cc)} → ${a.site}` : `${a.site} → ${cname(a.cc)}` }),
        row("Direction", a.dir === "in" ? "Inbound (Internet → servers)" : "Outbound (servers → Internet)"),
        row("Volume", `${fmtBytes(b)} · avg ${fmtBps(b * 8 / last.span)}`), row("Window", win()),
        row("Endpoint", `${cname(a.cc)} — country centroid, approximate`), row("Security", secLine(a.cc)),
        el("div", { class: "muted small", text: "Click to filter by this country" })];
    }
    function localTip(L) {
      const tin = d3.sum(L.items, (x) => x.c.in_b), tout = d3.sum(L.items, (x) => x.c.out_b);
      return [el("div", { class: "t", text: `Near ${L.site}: ${L.items.map((x) => cname(x.c.cc)).join(", ")}` }),
        row(sw("in", "Inbound"), `${fmtBytes(tin)} · avg ${fmtBps(tin * 8 / last.span)}`),
        row(sw("out", "Outbound"), `${fmtBytes(tout)} · avg ${fmtBps(tout * 8 / last.span)}`), row("Window", win()),
        row("Location", "same country as the site (GeoIP country only)"), ...L.items.map((x) => row("Security", secLine(x.c.cc))),
        el("div", { class: "muted small", text: "Remote endpoints are somewhere in this country — not at the site. Click to filter." })];
    }
    function alertTip(m, pin) {
      const items = m.a.items || [];
      const x = pin ? el("button", { class: "x", "aria-label": "Close", text: "✕" }) : null;
      if (x) x.addEventListener("click", unpin);
      return [x,
        el("div", { class: "t", text: `Security findings · ${cname(m.cc)}` }),
        el("div", { class: "muted small", text: `${m.local ? "Marker beside the site: these endpoints are in the site's own country (GeoIP country only)" : "Marker at the country centroid (approximate)"}. Only the endpoints listed are implicated.` }),
        ...items.slice(0, 4).map((x) => el("div", { class: "al" }, NM.sev(x.severity), " ",
          pin ? el("a", { href: `/netmon/alert/${x.id}`, text: x.title }) : el("span", { text: x.title }),
          el("div", { class: "muted small", text: `endpoint ${x.endpoints.join(", ")}${x.asset_label ? ` · server ${x.asset_label}` : ""} · ${NM.ago(Date.now() / 1000 - x.last_seen)}` }))),
        items.length > 4 ? el("div", { class: "muted small", text: `+ ${items.length - 4} more` }) : null,
        el("div", { class: "muted small", text: pin ? "Open a finding for its evidence" : "Click the marker for links to the evidence" })];
    }
    function show(ev, kids, pin = false) {
      if (!kids) return;
      tip.replaceChildren(...kids.filter(Boolean)); tip.hidden = false; tip.classList.toggle("pinned", pin);
      const [mx, my] = ev.at || d3.pointer(ev, node);
      let left = mx + 16; if (left + tip.offsetWidth > node.clientWidth) left = mx - tip.offsetWidth - 16;
      let top = my - 10; if (top + tip.offsetHeight > node.clientHeight) top = node.clientHeight - tip.offsetHeight - 4;
      // keep it inside the viewport too (the map can be scrolled partly off screen)
      const r = node.getBoundingClientRect();
      top = Math.min(top, window.innerHeight - r.top - tip.offsetHeight - 4); top = Math.max(top, -r.top + 4);
      tip.style.left = `${Math.max(0, Math.min(left, node.clientWidth - tip.offsetWidth))}px`; tip.style.top = `${Math.max(0, top)}px`;
    }
    function hide() { if (!pinned) { tip.hidden = true; tipFor = null; } }
    function unpin() { pinned = false; if (tip) { tip.hidden = true; tip.classList.remove("pinned"); } }

    async function render(data) {
      await ready;
      last = { ...data, byCc: Object.fromEntries(data.countries.map((c) => [c.cc, c])), alerts: data.alerts || {},
        blocked: data.blocked ? { in: new Set(data.blocked.in), out: new Set(data.blocked.out) } : null,
        policySites: data.policySites ? data.policySites.map((p) => ({ ...p, in: new Set(p.blocked_in), out: new Set(p.blocked_out) })) : null };
      const vals = (st.shade === "blocks" ? Object.keys((data.blocks && data.blocks.countries) || {}).map(nBlk) : data.countries.map(val)).filter((v) => v > 0);
      const lo = d3.min(vals) || 1, hi = Math.max(d3.max(vals) || 1, lo * 10);
      const ramp = st.shade === "alerts" ? ["--alert-lo", "--alert-hi"] : ["--shade-lo", "--shade-hi"];
      const color = d3.scaleSequentialLog(d3.interpolateLab(NM.css(ramp[0]), NM.css(ramp[1]))).domain([lo, hi]).clamp(true);
      const byBlock = st.shade === "blocked" && (last.blocked || last.policySites);
      gC.selectAll("path").attr("fill", (f) => { if (byBlock) { const k = blk(f.properties.cc);
          return k === "unknown" || k === "mixed" ? "url(#nm-unk)" : k ? `url(#nm-blk-${k})` : "var(--map-empty)"; }
        const v = st.shade === "blocks" ? nBlk(f.properties.cc) : val(last.byCc[f.properties.cc]); return v > 0 ? color(v) : "var(--map-empty)"; })
        .classed("sel", (f) => !!f.properties.cc && f.properties.cc === data.selected);

      // Arcs run site -> country centroid. Colour = direction only; findings are separate markers, never a red arc.
      // The site's own country (and centroids within a few px) has no meaningful arc: it becomes a ring around the site.
      const sites = data.sites || [], home = sites[0];
      const homeCc = home ? (features.find((f) => f.properties.cc && d3.geoContains(f, [home.lon, home.lat])) || { properties: {} }).properties.cc : null;
      const ranked = data.countries.filter((c) => c.ll && c.cc !== "??").map((c) => ({ c, v: vol(c, st.dir) })).filter((x) => x.v > 0).sort((a, b) => b.v - a.v);
      const arcs = [], local = { site: home && home.name, items: [] };
      const p0 = home ? proj([home.lon, home.lat]) : null;
      const far = [];
      for (const x of ranked) {
        if (!p0 || policyOnly) break;
        const p1 = proj([x.c.ll[1], x.c.ll[0]]);
        if (x.c.cc === homeCc || (p1 && Math.hypot(p1[0] - p0[0], p1[1] - p0[1]) < 18)) local.items.push(x); else if (p1) far.push({ ...x, p1 });
      }
      const shown = far.slice(0, 8), rest = far.slice(8);
      const maxV = d3.max([...shown, ...local.items], (x) => Math.max(x.c.in_b, x.c.out_b)) || 1;
      const w = d3.scaleSqrt().domain([0, maxV]).range([0.8, 5]);
      for (const { c, p1 } of shown) {
        const d = Math.hypot(p1[0] - p0[0], p1[1] - p0[1]);
        for (const dir of st.dir === "both" ? ["in", "out"] : [st.dir]) {
          const bytes = dir === "in" ? c.in_b : c.out_b; if (!bytes) continue;
          const sign = dir === "in" ? 1 : -1, bend = Math.min(0.22, 30 / d + 0.08);
          const mx = (p0[0] + p1[0]) / 2 - sign * (p1[1] - p0[1]) * bend, my = (p0[1] + p1[1]) / 2 + sign * (p1[0] - p0[0]) * bend - d * 0.1;
          arcs.push({ key: c.cc + dir, dir, cc: c.cc, site: home.name, w: w(bytes),
            d: dir === "in" ? `M${p1[0]},${p1[1]} Q${mx},${my} ${p0[0]},${p0[1]}` : `M${p0[0]},${p0[1]} Q${mx},${my} ${p1[0]},${p1[1]}` });
        }
      }
      gA.selectAll("path").data(arcs, (a) => a.key).join("path")
        .attr("class", (a) => `arc ${a.dir}${reduce ? "" : " anim"}`).attr("d", (a) => a.d)
        .attr("stroke-width", (a) => a.w).attr("vector-effect", "non-scaling-stroke")
        .on("pointermove", (ev, a) => !pinned && show(ev, arcTip(a))).on("pointerleave", hide)
        .on("click", (ev, a) => { unpin(); if (onSelect) onSelect(a.cc); });

      // local ring: inbound share teal, outbound share purple, thickness = volume
      gL.selectAll("*").remove();
      if (p0 && local.items.length) {
        const tin = d3.sum(local.items, (x) => st.dir === "out" ? 0 : x.c.in_b), tout = d3.sum(local.items, (x) => st.dir === "in" ? 0 : x.c.out_b);
        if (tin + tout > 0) {
          const t = Math.max(2.5, w(Math.max(tin, tout))), r0 = 12, split = 2 * Math.PI * tin / (tin + tout);
          const arc = d3.arc().innerRadius(r0).outerRadius(r0 + t);
          const gg = gL.append("g").attr("transform", `translate(${p0[0]},${p0[1]})`);
          if (tin) gg.append("path").attr("class", "local-in").attr("d", arc({ startAngle: 0, endAngle: split }));
          if (tout) gg.append("path").attr("class", "local-out").attr("d", arc({ startAngle: split, endAngle: 2 * Math.PI }));
          gg.append("circle").attr("class", "localhit").attr("r", r0 + t + 3)
            .on("pointermove", (ev) => !pinned && show(ev, localTip(local))).on("pointerleave", hide)
            .on("click", () => { unpin(); if (onSelect && local.items.length === 1) onSelect(local.items[0].c.cc); });
        }
      }
      gS.selectAll("*").remove();
      for (const s of sites) { const [x, y] = proj([s.lon, s.lat]);
        gS.append("circle").attr("class", "site").attr("cx", x).attr("cy", y).attr("r", 5).attr("vector-effect", "non-scaling-stroke").style("pointer-events", "none");
        gS.append("text").attr("class", "site-t").attr("x", x + 14 + (s === home && local.items.length ? 10 : 0)).attr("y", y + 4).text(s.name); }

      // red = evidence-backed findings only: one marker per country whose endpoints are named in an open finding
      const marks = policyOnly ? [] : Object.entries(last.alerts).filter(([cc, a]) => a.security > 0 && (a.items || []).length).map(([cc, a]) => {
        let p = null;
        if (cc === homeCc && p0) p = [p0[0] + 22, p0[1] - 20];
        else { const c = last.byCc[cc], ll = (c && c.ll) || (meta[cc] && meta[cc].ll); if (ll) p = proj([ll[1], ll[0]]); }
        return p ? { cc, a, p, local: cc === homeCc } : null; }).filter(Boolean);
      gM.selectAll("g").data(marks, (m) => m.cc).join((en) => { const gg = en.append("g");
          gg.append("circle").attr("class", "amark-ring").attr("r", 9); gg.append("path").attr("class", "amark").attr("d", d3.symbol(d3.symbolDiamond, 70)());
          gg.append("circle").attr("class", "amark-hit").attr("r", 12).attr("fill", "transparent").style("cursor", "pointer"); return gg; })
        .attr("transform", (m) => `translate(${m.p[0]},${m.p[1]})`)
        .on("pointermove", (ev, m) => !pinned && show(ev, alertTip(m, false))).on("pointerleave", hide)
        .on("click", (ev, m) => { ev.stopPropagation(); pinned = true; show(ev, alertTip(m, true), true); });

      const unknown = data.countries.find((c) => c.cc === "??");
      const restB = rest.reduce((s, x) => s + x.v, 0);
      const lg = data.legendNode;
      const policyLegend = () => [
        ...[["in", `Configured block · inbound (${last.blocked.in.size})`], ["out", `Configured block · outbound (${last.blocked.out.size})`], ["both", "Both directions"]]
          .filter(([k]) => k !== "both" || [...last.blocked.in].some((c) => last.blocked.out.has(c)))
          .map(([k, t]) => el("span", { class: "item" }, el("span", { class: `blksw ${k}` }), t)),
        el("span", { class: "item" }, el("span", { class: "blksw", style: "background:var(--map-empty)" }), "Not in block policy"),
        el("span", { class: "item", title: "No ISO code of its own (e.g. N. Cyprus, Somaliland, Crimea), a firewall's policy unreadable, or firewalls that differ" },
          el("span", { class: "blksw unk" }), "Unknown / mixed"),
        el("span", { class: "item muted small" }, "Patterns show configured policy, not verified enforcement")];
      const rampLegend = (label, lo, hi, fmt) => el("span", { class: "item" }, `${label} `,
        el("span", { class: "ramp", style: `background:linear-gradient(90deg,${NM.css(ramp[0])},${NM.css(ramp[1])})` }), ` ${fmt(lo)}–${fmt(hi)}`);
      if (lg && policyOnly && last.blocked) lg.replaceChildren(
        ...(st.shade === "blocked" ? policyLegend() : st.shade === "blocks"
          ? [rampLegend("Logged block events", lo, hi, fmtNum), el("span", { class: "item muted small" }, "firewall log records, not attacks or connections")]
          : [rampLegend("Observed traffic", lo, hi, fmtBytes)]),
        el("span", { class: "item" }, el("span", { class: "lgdot site" }), "Site"));
      else if (lg) lg.replaceChildren(
        el("span", { class: "item" }, el("span", { class: "arcsw in" }), "Inbound"),
        el("span", { class: "item" }, el("span", { class: "arcsw out" }), "Outbound"),
        el("span", { class: "item" }, el("span", { class: "lgdot site" }), "Site"),
        local.items.length ? el("span", { class: "item", title: "Traffic with endpoints in the site's own country; GeoIP gives the country only, so it is drawn as a ring, not an arc" },
          el("span", { class: "lgdot local" }), `Same country (${local.items.map((x) => x.c.cc).join(", ")})`) : null,
        el("span", { class: "item", title: "Country with endpoints named in an open medium+ finding. Arcs are never red." }, el("span", { class: "lgdiamond" }), "Security finding"),
        ...(byBlock && last.blocked ? policyLegend() : st.shade === "blocks" ? [rampLegend("Logged block events", lo, hi, fmtNum)] :
        [el("span", { class: "item" }, st.shade === "alerts" ? "Findings " : st.shade === "flows" ? "Flows " : "Bytes ",
          el("span", { class: "ramp", style: `background:linear-gradient(90deg,${NM.css(ramp[0])},${NM.css(ramp[1])})` }),
          st.shade === "alerts" ? " more" : ` ${st.shade === "flows" ? fmtNum(lo) : fmtBytes(lo)}–${st.shade === "flows" ? fmtNum(hi) : fmtBytes(hi)}`)]));
      if (data.noteNode) data.noteNode.replaceChildren(
        el("p", { text: `Arcs: top ${shown.length} countries by ${st.dir === "both" ? "total" : st.dir + "bound"} volume, from ${home ? home.name : "the site"} to each country's centroid. ` +
          "Line width = volume; teal = inbound, purple = outbound. Arcs show communication aggregated over the window — not routes, packets, or real-time paths." }),
        el("p", { text: `Locations are country-level GeoIP (no city): every endpoint is drawn at its country's centroid, so arc ends are approximate. ` +
          (local.items.length ? `Traffic with ${local.items.map((x) => cname(x.c.cc)).join(", ")} is the ring around the site — not a loop and not traffic returning to the site. ` : "") +
          (home ? `${home.name}: ${home.source}.` : "") }),
        el("p", { text: (rest.length ? `${rest.length} more countries (${fmtBytes(restB)}) appear as shading only. ` : "") +
          (unknown ? `No GeoIP country: ${fmtBytes(unknown.in_b + unknown.out_b)} (not mapped). ` : "") +
          "Only public Internet endpoints at the WAN boundary are mapped; internal addresses never are." }),
        el("p", { text: "Red ◆ = an open security finding (medium+ severity and confidence) names endpoints in that country. It marks those findings only — other traffic with the country is not implicated." }));
    }
    return {
      render, setDir: (d) => { st.dir = d; if (last) render(last); }, setShade: (s) => { st.shade = s; if (last) render(last); },
      zoomBy: (k) => svg && svg.transition().duration(reduce ? 0 : 250).call(zoom.scaleBy, k), reset: () => svg && svg.transition().duration(reduce ? 0 : 250).call(zoom.transform, d3.zoomIdentity),
    };
  }
  function bindControls(map) {
    const dir = document.getElementById("mapdir"), shade = document.getElementById("mapshade");
    let cur = "both"; try { cur = localStorage.getItem("nm.mapdir") || "both"; } catch (_) {}
    const mark = () => dir && dir.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.v === cur));
    if (dir) dir.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; cur = b.dataset.v;
      try { localStorage.setItem("nm.mapdir", cur); } catch (_) {} mark(); map.setDir(cur); });
    mark(); map.setDir(cur);
    if (shade) shade.addEventListener("change", () => map.setShade(shade.value));
    const z = (id, f) => { const b = document.getElementById(id); if (b) b.addEventListener("click", f); };
    z("zoomin", () => map.zoomBy(1.6)); z("zoomout", () => map.zoomBy(1 / 1.6)); z("zoomreset", () => map.reset());
  }
  return { create, bindControls, meta: async () => { await assets(); return meta; } };
})();
