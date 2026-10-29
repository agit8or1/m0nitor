"use strict";
(() => {
  const { el, $, fmtNum, fmtTime } = NM;
  let page = 1, action = "block";
  const seg = $("fwact"); const mark = () => seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.v === action));
  seg.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; action = b.dataset.v; page = 1; mark(); load(); });
  const countChart = (node, pts) => { // reuse line chart: counts per bucket, labelled as events
    node.replaceChildren(); if (!pts.length) return NM.state(node, "empty", "No firewall events in this window");
    const W = node.clientWidth || 800, H = 240, m = { t: 12, r: 90, b: 26, l: 60 };
    const svg = d3.select(node).append("svg").attr("viewBox", `0 0 ${W} ${H}`);
    const x = d3.scaleTime().domain(d3.extent(pts, (p) => new Date(p.t * 1000))).range([m.l, W - m.r]);
    const y = d3.scaleLinear().domain([0, d3.max(pts, (p) => Math.max(p.blocked, p.passed)) * 1.1 || 1]).nice().range([H - m.b, m.t]);
    svg.append("g").selectAll("line").data(y.ticks(4)).join("line").attr("class", "gridline").attr("x1", m.l).attr("x2", W - m.r).attr("y1", y).attr("y2", y);
    svg.append("g").attr("class", "axis").attr("transform", `translate(${m.l},0)`).call(d3.axisLeft(y).ticks(4).tickFormat(d3.format("~s")).tickSize(0).tickPadding(8)).call((g) => g.select(".domain").remove());
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b})`).call(d3.axisBottom(x).ticks(6).tickSizeOuter(0));
    for (const [k, cls, lab] of [["blocked", "out", "Blocked"], ["passed", "in", "Allowed (logged)"]]) {
      svg.append("path").datum(pts).attr("class", `line ${cls}`).attr("d", d3.line().x((p) => x(new Date(p.t * 1000))).y((p) => y(p[k])));
      svg.append("text").attr("class", "endlabel").attr("x", W - m.r + 6).attr("y", y(pts[pts.length - 1][k]) + (k === "blocked" ? -4 : 12)).text(lab);
    }
  };
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/firewall?${NM.qs({ page_: page, action })}`);
      NM.scopeDesc(d.scope);
      const f = d.sources.fw;
      $("fwstate").replaceChildren(f.last ? "" : el("div", { class: "banner warn" }, el("b", { text: "Firewall logs not connected. " }),
        "Blocked/allowed counts are unavailable — not zero. ", el("a", { href: "/netmon/settings/integrations", text: "Set up OPNsense remote syslog →" })));
      const tot = (a) => d.totals.filter((t) => t.action === a).reduce((s, t) => s + +t.n, 0);
      NM.cards($("cards"), [
        { k: "Blocked", sw: "--out", href: "#t-recent", v: fmtNum(tot("block")), s: "firewall decisions in window" },
        { k: "Allowed (logged rules only)", sw: "--in", href: "#t-recent", v: fmtNum(tot("pass")), s: "unlogged passes are not counted" },
        { k: "Distinct blocked sources", href: "#t-src", v: fmtNum(d.top_sources.length >= 15 ? "15+" : d.top_sources.length), s: "top list below" },
        { k: "Log feed", href: "/netmon/settings/integrations", v: f.last ? "Connected" : "Not connected", s: f.last ? `last line ${NM.ago(Date.now() / 1000 - f.last)}` : "remote syslog" },
      ]);
      countChart($("fwts"), d.series.map((p) => ({ t: p.t, blocked: +p.blocked, passed: +p.passed })));
      $("fwlegend").replaceChildren(el("span", { class: "item" }, el("span", { class: "sw", style: "background:var(--out)" }), "Blocked"),
        el("span", { class: "item" }, el("span", { class: "sw", style: "background:var(--in)" }), "Allowed (logged)"));
      NM.rank($("t-src"), d.top_sources.map((r) => ({ ...r, in_b: +r.n, out_b: 0 })), { label: (r) => r.name || r.ip, sub: (r) => `${fmtNum(r.ports)} ports · ${fmtNum(r.targets)} targets`,
        link: (r) => NM.href("/netmon/connections", { rip: r.ip }), value: (r) => fmtNum(r.n), empty: "No events" });
      NM.rank($("t-ports"), d.top_ports.map((r) => ({ ...r, in_b: +r.n, out_b: 0 })), { label: (r) => `${r.proto}/${r.dport}`, sub: (r) => `${fmtNum(r.sources)} sources`, value: (r) => fmtNum(r.n), empty: "No events" });
      NM.rank($("t-lan"), d.lan_blocked.map((r) => ({ ...r, in_b: +r.n, out_b: 0 })), { label: (r) => r.name || r.ip, sub: (r) => `${fmtNum(r.dsts)} destinations · ports ${r.ports.join(", ")}`,
        link: (r) => NM.href(`/netmon/servers/${r.ip}`), value: (r) => fmtNum(r.n), empty: "No internal host was blocked" });
      NM.table($("t-tot"), [{ label: "Decision", get: (r) => r.action }, { label: "Direction", get: (r) => r.dir }, { label: "Interface", get: (r) => r.iface },
        { label: "Events", cls: "num", get: (r) => fmtNum(r.n) }], d.totals.slice(0, 12), { empty: "No events" });
      NM.table($("t-recent"), [
        { label: "Time", cls: "num", get: (r) => fmtTime(r.ms / 1000, true) },
        { label: "Decision", get: (r) => el("span", { class: `sev s-${r.action === "block" ? "serious" : "good"}`, text: r.action === "block" ? "◆ blocked" : "● allowed" }) },
        { label: "Dir / iface", get: (r) => `${r.dir} · ${r.iface}` }, { label: "Source", get: (r) => `${r.src}${r.sport ? ":" + r.sport : ""}` },
        { label: "Destination", get: (r) => `${r.dst}${r.dport ? ":" + r.dport : ""}` }, { label: "Proto", get: (r) => r.proto + (r.tcpflags ? ` [${r.tcpflags}]` : "") },
        { label: "Rule", get: (r) => el("span", { title: r.rid, text: `#${r.rulenr}` }) }], d.recent, { empty: "No events in this window" });
      NM.pager($("pager"), d.page, 50, d.recent.length < 50 ? (d.page - 1) * 50 + d.recent.length : d.page * 50 + 1, (p) => { page = p; load(); });
    } catch (e) { NM.state($("cards"), "error", e.message); }
  }
  mark(); NM.onScope(() => { page = 1; load(); }); load(); NM.every(load, 30000);
})();
