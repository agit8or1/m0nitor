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
      zoom = d3.zoom().scaleExtent([1, 24]).translateExtent([[0, 0], [W, H]]).on("zoom", (ev) => { g.attr("transform", ev.transform); rescale(ev.transform.k); });
      svg.call(zoom).on("dblclick.zoom", null);
    }
    // Symbols (dots, site, labels, finding markers) keep their screen size while the map zooms, so zooming in pulls
    // neighbouring sources apart instead of enlarging them together.
    function rescale(k) {
      if (!g) return;
      g.selectAll("[data-r0]").attr("r", function () { return +this.dataset.r0 / k; });
      g.selectAll("text[data-x0]").attr("x", function () { return +this.dataset.x0 + +this.dataset.dx / k; })
        .attr("y", function () { return +this.dataset.y0 + +this.dataset.dy / k; })
        .style("font-size", function () { return `${+this.dataset.fs / k}px`; }).style("stroke-width", `${3 / k}px`);
      gM.selectAll("g").attr("transform", (m) => `translate(${m.p[0] + (m.off ? m.off[0] / k : 0)},${m.p[1] + (m.off ? m.off[1] / k : 0)}) scale(${1 / k})`);
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
    const fill = (n, ...kids) => n.replaceChildren(...kids.flat().filter(Boolean));   // null = nothing, never the text "null"
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
    const CITY = "city-level GeoIP (DB-IP Lite), approximate";
    // busiest source -> destination address pairs behind an arc, region, endpoint or the site's own country
    function pairRows(list, dir) {
      const ps = (list || []).filter((p) => !dir || dir === "both" || p.dir === dir).sort((a, b) => b.b - a.b).slice(0, 5);
      if (!ps.length) return [];
      // "[WAN / WAN alias x | name] public address (reverse DNS) → internal server(s) behind it"
      // in flow order: inbound "… ⟶ WAN alias x 1.2.3.4 (rdns) → server", outbound "server → WAN alias x 1.2.3.4 (rdns) ⟶ …"
      const names = (n) => n && n.length ? `${n.slice(0, 3).join(", ")}${n.length > 3 ? ` +${n.length - 3}` : ""}` : "";
      const ip = (p, k) => { const n = names(p[`${k}_inner`]);
        return [k === "src" && n ? `${n} →` : "", p[`${k}_fw`] || p[`${k}_name`], p[k], p[`${k}_rdns`] ? `(${p[`${k}_rdns`]})` : "",
          k === "dst" && n ? `→ ${n}` : ""].filter(Boolean).join(" "); };
      return [el("div", { class: "muted small", style: "margin-top:4px", text: "Top source → destination" }),
        ...ps.map((p) => el("div", { class: "small mono pair", text: `${ip(p, "src")}  ⟶  ${ip(p, "dst")} · ${fmtBytes(p.b)}` }))];
    }
    function arcTip(a) {
      const t = a.t, c = t.c;
      if (t.kind === "point") return pointTip(c, a.dir);
      const b = a.dir === "in" ? c.in_b : c.out_b;
      return [el("div", { class: "t", text: a.dir === "in" ? `${cname(c.cc)} → ${a.site}` : `${a.site} → ${cname(c.cc)}` }),
        row("Direction", a.dir === "in" ? "Inbound (Internet → servers)" : "Outbound (servers → Internet)"),
        row("Volume", `${fmtBytes(b)} · avg ${fmtBps(b * 8 / last.span)}`), row("Window", win()),
        row("Endpoint", `${cname(c.cc)} — country centroid, approximate`),
        c.resid ? row("Shown here", "the part of this country's traffic not placed by city") : null,
        row("Security", secLine(c.cc)), ...pairRows(c.pairs, a.dir),
        el("div", { class: "muted small", text: "Click to filter by this country" })];
    }
    // a region (several endpoints in the site's own country) or one endpoint of a finding
    function pointTip(x, dir) {
      const where = x.ip ? [x.city, x.region, cname(x.cc)].filter(Boolean).join(", ") : `${x.region}, ${cname(x.cc)}`;
      const title = x.ip ? `${x.name && x.name !== x.ip ? `${x.name} ${x.ip}` : x.ip}${x.rdns ? ` (${x.rdns})` : ""}` : where;
      const site = last.sites && last.sites[0] ? last.sites[0].name : "site";
      return [el("div", { class: "t", text: dir === "in" ? `${title} → ${site}` : dir === "out" ? `${site} → ${title}` : title }),
        x.ip ? row("Location", where || cname(x.cc)) : row("Cities", (x.cities || []).join(", ") || "—"),
        x.asname ? row("Organization", x.asname) : null,
        row(sw("in", "Inbound"), `${fmtBytes(x.in_b)} · avg ${fmtBps(x.in_b * 8 / last.span)}`),
        row(sw("out", "Outbound"), `${fmtBytes(x.out_b)} · avg ${fmtBps(x.out_b * 8 / last.span)}`),
        x.ip ? row("Flows", fmtNum(x.flows || 0)) : row("Endpoints", `${fmtNum(x.peers)} of the busiest in ${cname(x.cc)}`),
        x.ports && x.ports.length ? row("Ports", x.ports.slice(0, 8).join(", ")) : null,
        x.blocked && !x.in_b && !x.out_b ? row("Firewall", `${fmtNum(x.events || 0)} logged blocked packets — blocked, so no flows`) : null,
        x.named ? row("Finding", "named in this finding's evidence") : null,
        x.named && !x.in_b && !x.out_b && !x.blocked ? row("Flows", "none in the evidence window (it may have aged out or fallen between flow exports)") : null,
        row("Placed by", CITY), row("Window", win()), ...pairRows(x.pairs, dir),
        el("div", { class: "muted small", text: x.href ? "Click to open its connections" : "Click to filter by this country" })];
    }
    function localTip(L) {
      const all = [...L.items, ...L.pts], tin = d3.sum(all, (x) => x.c.in_b), tout = d3.sum(all, (x) => x.c.out_b);
      const names = [...new Set([...L.items.map((x) => cname(x.c.cc)), ...L.pts.map((x) => x.c.region || x.c.city || x.c.ip)])];
      return [el("div", { class: "t", text: `Near ${L.site}: ${names.slice(0, 4).join(", ")}${names.length > 4 ? " …" : ""}` }),
        row(sw("in", "Inbound"), `${fmtBytes(tin)} · avg ${fmtBps(tin * 8 / last.span)}`),
        row(sw("out", "Outbound"), `${fmtBytes(tout)} · avg ${fmtBps(tout * 8 / last.span)}`), row("Window", win()),
        row("Location", L.pts.length ? "close to the site, or in its country with no city location" : "same country as the site (GeoIP country only)"),
        ...[...new Set(L.items.map((x) => x.c.cc))].map((cc) => row("Security", secLine(cc))),
        ...pairRows(all.flatMap((x) => x.c.pairs || [])),
        el("div", { class: "muted small", text: "Remote endpoints are near the site or somewhere in its country — not at the site itself. Click to filter." })];
    }
    function alertTip(m, pin) {
      const items = m.a.items || [];
      const x = pin ? el("button", { class: "x", "aria-label": "Close", text: "✕" }) : null;
      if (x) x.addEventListener("click", unpin);
      return [x,
        el("div", { class: "t", text: `Security findings · ${cname(m.cc)}` }),
        el("div", { class: "muted small", text: `${m.at ? `Marker at the endpoint (${CITY})` : m.local ? "Marker beside the site: these endpoints are in the site's own country" : "Marker at the country centroid (approximate)"}. Only the endpoints listed are implicated.` }),
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

      // Arcs run site -> target. Targets are located endpoints or regions (city-level GeoIP: data.points on a finding page,
      // data.home.regions for the site's own country) and country centroids for whatever traffic is not placed more
      // precisely. Colour = direction only; findings are separate markers, never a red arc. Traffic that would land on the
      // site itself (its own country without a region, or anything within a few px) is the ring around the site.
      const sites = data.sites || [], home = sites[0];
      const homeCc = home ? (home.cc || (features.find((f) => f.properties.cc && d3.geoContains(f, [home.lon, home.lat])) || { properties: {} }).properties.cc) : null;
      const p0 = home ? proj([home.lon, home.lat]) : null;
      const pts = (data.points || (data.home && data.home.cc === homeCc ? data.home.regions : null) || []).filter((x) => x.ll);
      const placed = {};
      for (const x of pts) { const k = placed[x.cc] || (placed[x.cc] = { in_b: 0, out_b: 0 }); k.in_b += x.in_b; k.out_b += x.out_b; }
      const resid = (c) => { const k = placed[c.cc]; return k ? { ...c, in_b: Math.max(0, c.in_b - k.in_b), out_b: Math.max(0, c.out_b - k.out_b), resid: true } : c; };
      const near = (p1) => Math.hypot(p1[0] - p0[0], p1[1] - p0[1]) < 18;
      const local = { site: home && home.name, items: [], pts: [] }, farC = [], farP = [];
      if (p0 && !policyOnly) {
        for (const c0 of data.countries) {
          if (!c0.ll || c0.cc === "??") continue;
          const c = resid(c0), v = vol(c, st.dir), p1 = proj([c.ll[1], c.ll[0]]);
          if (v <= 0 || !p1) continue;
          if (c.cc === homeCc || near(p1)) local.items.push({ c, v }); else farC.push({ kind: "country", key: c.cc, c, v, p1 });
        }
        for (const x of pts) {
          const v = vol(x, st.dir), p1 = proj([x.ll[1], x.ll[0]]);
          if (!p1 || (v <= 0 && !x.named && !(x.blocked && st.dir !== "out"))) continue;   // named endpoints always shown
          if (near(p1)) local.pts.push({ c: x, v }); else farP.push({ kind: "point", key: `p:${x.key}`, c: x, v, p1 });
        }
      }
      farC.sort((a, b) => b.v - a.v); farP.sort((a, b) => b.v - a.v);
      const nP = data.points ? 30 : 10;
      const shown = farC.slice(0, 8), rest = farC.slice(8), shownP = farP.slice(0, nP), restP = farP.slice(nP);
      const tin = d3.sum([...local.items, ...local.pts], (x) => st.dir === "out" ? 0 : x.c.in_b);
      const tout = d3.sum([...local.items, ...local.pts], (x) => st.dir === "in" ? 0 : x.c.out_b);
      const maxV = d3.max([...shown, ...shownP].map((x) => Math.max(x.c.in_b, x.c.out_b)).concat([tin, tout])) || 1;
      const w = d3.scaleSqrt().domain([0, maxV]).range([0.8, 5]);
      const arcs = [];
      for (const t of [...shown, ...shownP]) {
        const { c, p1 } = t, d = Math.hypot(p1[0] - p0[0], p1[1] - p0[1]);
        for (const dir of st.dir === "both" ? ["in", "out"] : [st.dir]) {
          const bytes = dir === "in" ? c.in_b : c.out_b, blocked = !bytes && dir === "in" && !!c.blocked;
          if (!bytes && !blocked) continue;
          const sign = dir === "in" ? 1 : -1, bend = Math.min(0.22, 30 / d + 0.08);
          const mx = (p0[0] + p1[0]) / 2 - sign * (p1[1] - p0[1]) * bend, my = (p0[1] + p1[1]) / 2 + sign * (p1[0] - p0[0]) * bend - d * 0.1;
          arcs.push({ key: t.key + dir, dir, t, site: home.name, w: blocked ? 1.2 : w(bytes), blocked,
            d: dir === "in" ? `M${p1[0]},${p1[1]} Q${mx},${my} ${p0[0]},${p0[1]}` : `M${p0[0]},${p0[1]} Q${mx},${my} ${p1[0]},${p1[1]}` });
        }
      }
      const pick = (t) => { unpin(); if (t.c.href) location.href = t.c.href; else if (onSelect) onSelect(t.c.cc); };
      gA.selectAll("path").data(arcs, (a) => a.key).join("path")
        .attr("class", (a) => `arc ${a.dir}${a.blocked ? " blk" : ""}${reduce || a.blocked ? "" : " anim"}`).attr("d", (a) => a.d)
        .attr("stroke-width", (a) => a.w).attr("vector-effect", "non-scaling-stroke")
        .on("pointermove", (ev, a) => !pinned && show(ev, arcTip(a))).on("pointerleave", hide)
        .on("click", (ev, a) => pick(a.t));
      // endpoint / region dots at the far end of point arcs
      gA.selectAll("circle").data(shownP, (t) => t.key).join("circle").attr("class", (t) => `pt${t.c.blocked && !t.v ? " blk" : ""}${t.c.named ? " named" : ""}`)
        .attr("cx", (t) => t.p1[0]).attr("cy", (t) => t.p1[1]).attr("data-r0", (t) => t.c.named ? 4.5 : 2.6).attr("vector-effect", "non-scaling-stroke")
        .on("pointermove", (ev, t) => !pinned && show(ev, pointTip(t.c, null))).on("pointerleave", hide)
        .on("click", (ev, t) => pick(t));

      // home-country / near-site traffic has no arc and no ring (the ring hid the site): an invisible hover target on the
      // site dot keeps its tooltip, and the numbers are in the label under the site name.
      gL.selectAll("*").remove();
      const homeC = homeCc && last.byCc[homeCc];
      if (p0 && tin + tout > 0)
        gL.append("circle").attr("class", "localhit").attr("cx", p0[0]).attr("cy", p0[1]).attr("data-r0", 9)
          .on("pointermove", (ev) => !pinned && show(ev, localTip(local))).on("pointerleave", hide)
          .on("click", () => { unpin(); if (onSelect && homeCc) onSelect(homeCc); });
      gS.selectAll("*").remove();
      for (const s of sites) { const [x, y] = proj([s.lon, s.lat]);
        const dx = 10;
        gS.append("circle").attr("class", "site").attr("cx", x).attr("cy", y).attr("data-r0", 5).attr("vector-effect", "non-scaling-stroke").style("pointer-events", "none");
        gS.append("text").attr("class", "site-t").attr("data-x0", x).attr("data-y0", y).attr("data-dx", dx).attr("data-dy", 1).attr("data-fs", 12).text(s.name);
        // the site's own country in numbers: it is usually most of the traffic and has no arc of its own
        if (s === home && homeC && !policyOnly && !data.points) gS.append("text").attr("class", "site-sub").attr("data-x0", x).attr("data-y0", y).attr("data-dx", dx).attr("data-dy", 14).attr("data-fs", 11)
          .text(`${homeCc} ⬇ ${fmtBytes(homeC.in_b)} ⬆ ${fmtBytes(homeC.out_b)}`); }

      // red = evidence-backed findings only: one marker per country whose endpoints are named in an open finding
      const marks = policyOnly ? [] : Object.entries(last.alerts).filter(([cc, a]) => a.security > 0 && (a.items || []).length).map(([cc, a]) => {
        let p = null;
        let off = null; if (cc === homeCc && p0) { p = p0; off = [22, -20]; }
        else { const c = last.byCc[cc], ll = (c && c.ll) || (meta[cc] && meta[cc].ll); if (ll) p = proj([ll[1], ll[0]]); }
        return p ? { key: cc, cc, a, p, off, local: cc === homeCc } : null; }).filter(Boolean);
      // a finding's named endpoints that city-level GeoIP places: the marker sits on the endpoint itself
      for (const x of policyOnly ? [] : pts) if (x.flag) {
        const p1 = proj([x.ll[1], x.ll[0]]); if (!p1) continue;
        marks.push({ key: `p:${x.key}`, cc: x.cc, a: { security: 1, items: [{ ...x.flag, endpoints: [x.ip] }] }, p: p0 && near(p1) ? p0 : p1, off: p0 && near(p1) ? [22, -20] : null, at: x });
      }
      gM.selectAll("g").data(marks, (m) => m.key).join((en) => { const gg = en.append("g");
          gg.append("circle").attr("class", "amark-ring").attr("r", 9).style("pointer-events", "none"); gg.append("path").attr("class", "amark").attr("d", d3.symbol(d3.symbolDiamond, 70)());
          gg.append("circle").attr("class", "amark-hit").attr("r", 7).attr("fill", "transparent").style("cursor", "pointer"); return gg; })
        .on("pointermove", (ev, m) => !pinned && show(ev, alertTip(m, false))).on("pointerleave", hide)
        .on("click", (ev, m) => { ev.stopPropagation(); pinned = true; show(ev, alertTip(m, true), true); });
      rescale(d3.zoomTransform(svg.node()).k);

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
      else if (lg) fill(lg,
        el("span", { class: "item" }, el("span", { class: "arcsw in" }), "Inbound"),
        el("span", { class: "item" }, el("span", { class: "arcsw out" }), "Outbound"),
        el("span", { class: "item" }, el("span", { class: "lgdot site" }), "Site"),
        shownP.some((t) => t.c.named) ? el("span", { class: "item", title: "Remote address this finding's evidence names" }, el("span", { class: "lgdot pt named" }), "Named in evidence") : null,
        shownP.length ? el("span", { class: "item", title: CITY }, el("span", { class: "lgdot pt" }), data.points ? "Endpoint (by city)" : `${cname(homeCc)} region (by city)`) : null,
        arcs.some((a) => a.blocked) ? el("span", { class: "item" }, el("span", { class: "arcsw blk" }), "Blocked by firewall (no flows)") : null,
        el("span", { class: "item", title: "Country with endpoints named in an open medium+ finding. Arcs are never red." }, el("span", { class: "lgdiamond" }), "Security finding"),
        ...(byBlock && last.blocked ? policyLegend() : st.shade === "blocks" ? [rampLegend("Logged block events", lo, hi, fmtNum)] :
        !vals.length ? [] : [el("span", { class: "item" }, st.shade === "alerts" ? "Findings " : st.shade === "flows" ? "Flows " : "Bytes ",
          el("span", { class: "ramp", style: `background:linear-gradient(90deg,${NM.css(ramp[0])},${NM.css(ramp[1])})` }),
          st.shade === "alerts" ? " more" : ` ${st.shade === "flows" ? fmtNum(lo) : fmtBytes(lo)}–${st.shade === "flows" ? fmtNum(hi) : fmtBytes(hi)}`)]));
      if (data.noteNode) fill(data.noteNode,
        el("p", { text: `Arcs: top ${shown.length} countries by ${st.dir === "both" ? "total" : st.dir + "bound"} volume, from ${home ? home.name : "the site"} to each country's centroid` +
          (shownP.length ? (data.points ? `, plus ${shownP.length} of this finding's remote endpoints at their own location. ` : `, plus the top ${shownP.length} regions of ${cname(homeCc)}. `) : ". ") +
          "Line width = volume; teal = inbound, purple = outbound. Arcs show communication aggregated over the window — not routes, packets, or real-time paths." }),
        el("p", { text: "Countries are counted by country-level GeoIP (the database Akvorado uses) and drawn at their centroid. " +
          (pts.length ? `${data.points ? "Endpoints" : `In ${cname(homeCc)}, the busiest endpoints`} are placed by city-level GeoIP (DB-IP Lite) — usually the ISP's registered city, so approximate` +
            (data.home && !data.points && data.home.covered ? `; regions cover ${Math.round(data.home.covered * 100)}% of ${cname(homeCc)} bytes` +
              (data.home.disputed > 0.05 ? `, and ${Math.round(data.home.disputed * 100)}% has no arc because the city database puts those addresses in another country (usually anycast CDNs, which have no single location)` : "") : "") + ". " : "") +
          (tin + tout ? "Traffic with endpoints next to the site, or in its own country with no city location, has no arc — hover the site to see it. " : "") +
          (home ? `${home.name}: ${home.source}.` : "") }),
        el("p", { text: (rest.length ? `${rest.length} more countries (${fmtBytes(restB)}) appear as shading only. ` : "") +
          (restP.length ? `${restP.length} more ${data.points ? "endpoints" : "regions"} (${fmtBytes(d3.sum(restP, (x) => x.v))}) are not drawn. ` : "") +
          (unknown ? `No GeoIP country: ${fmtBytes(unknown.in_b + unknown.out_b)} (not mapped). ` : "") +
          "Only public Internet endpoints at the WAN boundary are mapped; internal addresses never are." }),
        el("p", { text: "Red ◆ = an open security finding (medium+ severity and confidence) names endpoints there. It marks those findings only — other traffic with the country is not implicated." }),
        pts.length ? el("p", { class: "muted small", text: "IP geolocation by DB-IP (db-ip.com), CC BY 4.0." }) : null);
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
