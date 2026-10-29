// Finding page: the traffic behind one finding (map, ports, remote endpoints) and in-place AI analysis.
"use strict";
(() => {
  const { el, $, fmtBytes, fmtNum, fmtTime, ago } = NM;
  const box = $("ftraffic");
  if (box) {
    const aid = box.dataset.aid;
    const map = NMMap.create($("map"), { onSelect: (cc) => { location.href = NM.href("/netmon/connections", { cc }); } });
    NMMap.bindControls(map);
    // the ClickHouse services dictionary has dated names for a few ports; prefer what operators know them as
    const WELL_KNOWN = { 53: "dns", 853: "dns-over-tls", 5228: "google push (FCM)", 3478: "stun/turn", 8006: "proxmox", 51820: "wireguard", 0: "" };
    const portName = (p) => (33434 <= p.port && p.port <= 33534 && p.proto === "udp") ? "traceroute" : p.port in WELL_KNOWN ? WELL_KNOWN[p.port] : p.service;
    (async () => {
      try {
        const d = await NM.get(`/netmon/api/alert/${aid}/traffic`);
        const sc = d.scope;
        $("ftscope").textContent = `${fmtTime(sc.start, true)} → ${fmtTime(sc.end, true)} · ${d.subject_label || d.subject || "named peers"}`;
        map.render({ countries: d.countries, alerts: d.alert_countries, sites: d.sites, span: sc.span, window: "finding window",
          legendNode: $("maplegend"), noteNode: $("mapnote") });
        $("mapnote").prepend(el("p", { text: `Flows at the WAN boundary between ${d.subject_label || d.subject || "the site"} and the Internet during this finding's evidence window` +
          (d.peers.length ? `, plus any flow with the ${d.peers.length} remote address(es) the finding names (red ◆).` : ".") }));
        NM.table($("ft-ports"), [
          { label: "Port", cls: "num", get: (p) => String(p.port) },
          { label: "Service", get: (p) => portName(p) || el("span", { class: "muted", text: "—" }) },
          { label: "Proto", get: (p) => p.proto },
          { label: "Flows", cls: "num", get: (p) => fmtNum(p.flows) },
          { label: "Remotes", cls: "num", get: (p) => fmtNum(p.remotes) },
          { label: "Direction", get: (p) => p.in_flows && p.out_flows ? "both" : p.in_flows ? "⬇ to us" : "⬆ from us" },
          { label: "Bytes", cls: "num", get: (p) => fmtBytes(p.bytes) },
        ], d.ports.slice(0, 15), { empty: "No flows in this window (data may have aged out)" });
        const named = new Set(d.peers), PER = 10;
        const pager = el("div", { class: "pager" }); $("ft-remotes").after(pager);
        const show = (pg) => { NM.table($("ft-remotes"), REMOTE_COLS, d.remotes.slice((pg - 1) * PER, pg * PER), { empty: "No flows in this window (data may have aged out)" });
          NM.pager(pager, pg, PER, d.remotes.length, show); };
        const REMOTE_COLS = [
          { label: "Remote IP", get: (r) => el("span", {}, NM.ipCell(r.ip, r.name),
              named.has(r.ip) ? el("span", { class: "tag", title: "named in this finding's evidence", text: "in evidence" }) : null) },
          { label: "Country", get: (r) => r.cc_name || r.cc },
          { label: "Organization", get: (r) => r.asname || (r.asn ? `AS${r.asn}` : "—") },
          { label: "⬇ Received", cls: "num", get: (r) => r.in_b ? fmtBytes(r.in_b) : "—" },
          { label: "⬆ Sent", cls: "num", get: (r) => r.out_b ? fmtBytes(r.out_b) : "—" },
          { label: "Flows", cls: "num", get: (r) => fmtNum(r.flows) },
          { label: "Ports", get: (r) => el("span", { class: "mono", text: r.ports.slice(0, 8).join(", ") + (r.ports.length > 8 ? " …" : "") }) },
          { label: "Last seen", cls: "num", get: (r) => fmtTime(r.last, true) },
        ];
        show(1);
      } catch (e) { NM.state($("ft-remotes"), "error", `Could not load traffic: ${e.message}`); }
    })();
  }

  // ---- AI analysis in place: preview exactly what is sent, then send ----
  const ai = $("aibox");
  if (!ai) return;
  const enabled = ai.dataset.enabled === "1";
  const go = $("aigo");
  if (!enabled) { go.disabled = true; go.title = "AI analysis is not configured"; }
  go.addEventListener("click", async () => {
    const pv = $("aipreview"); $("airesult").replaceChildren(); NM.state(pv, "loading", "Building minimized evidence…"); go.disabled = true;
    try {
      const d = await NM.get(`/netmon/api/ai/preview?kind=alert&target=${encodeURIComponent(ai.dataset.aid)}`);
      const send = el("button", { class: "primary", text: `Send to OpenAI (${d.model})` });
      pv.replaceChildren(
        el("details", {}, el("summary", { text: `Evidence to be sent: ${d.chars.toLocaleString()} characters · ${d.pseudonyms} internal identifier(s) pseudonymized — review` }),
          el("p", { class: "muted small", text: d.note }), el("pre", { class: "preview", text: JSON.stringify(d.body, null, 1) })),
        el("div", { class: "row", style: "margin-top:10px" }, send));
      send.addEventListener("click", async () => {
        send.disabled = true; NM.state($("airesult"), "loading", "Waiting for the model…");
        const fd = new FormData(); fd.set("digest", d.digest); fd.set("csrf", $("csrf").value);
        try {
          const r = await fetch("/netmon/api/ai/send", { method: "POST", body: fd, credentials: "same-origin" });
          const j = await r.json();
          if (!j.ok) { send.disabled = false; return NM.state($("airesult"), "error", j.error || j.detail || "failed"); }
          showResult(j);
        } catch (e) { send.disabled = false; NM.state($("airesult"), "error", e.message); }
      });
    } catch (e) { NM.state(pv, "error", e.message); } finally { go.disabled = !enabled; }
  });
  const saved = $("aisaved");
  if (saved) { try { showResult(JSON.parse(saved.textContent)); } catch (e) { /* malformed saved row: leave the box empty */ } }
  function showResult(j) {
    const x = j.result, u = j.usage || {};
    $("aipreview").replaceChildren();
    $("airesult").replaceChildren(
      x.threat_score != null ? el("div", { class: "scorebox" },
        el("div", { class: "scorehead" }, el("b", { text: `AI threat score: ${x.threat_score} / 100` }),
          el("span", { class: "muted small", text: x.threat_score >= 81 ? " strong evidence of malicious activity" : x.threat_score >= 61 ? " probably malicious or unauthorized"
            : x.threat_score >= 41 ? " cannot tell from this evidence" : x.threat_score >= 21 ? " probably benign" : " almost certainly benign / expected" })),
        el("div", { class: "scorebar", role: "meter", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": x.threat_score, "aria-label": "AI threat score" },
          el("span", { style: `width:${x.threat_score}%` })),
        el("p", { class: "small", text: x.score_rationale || "" }),
        el("p", { class: "muted small", text: "Model estimate from metadata only — not a verdict. Each analysis is kept, so the score's history is shown on this finding." })) : null,
      el("h3", { text: "Summary" }), el("p", { text: x.summary }),
      x.hypotheses && x.hypotheses.length ? el("h3", { text: "Hypotheses" }) : null,
      el("ul", {}, (x.hypotheses || []).filter((h) => h.hypothesis && h.hypothesis.trim()).map((h) => el("li", {}, el("b", { text: `${h.likelihood}: ` }), h.hypothesis,
        h.supporting_evidence_ids && h.supporting_evidence_ids.length ? el("span", { class: "muted small", text: ` (${h.supporting_evidence_ids.join(", ")})` }) : null))),
      (x.recommendations || []).some((s) => s && s.trim()) ? el("h3", { text: "Recommended investigation steps" }) : null,
      el("ol", {}, (x.recommendations || []).filter((s) => s && s.trim()).map((s) => el("li", { text: s }))),
      x.uncertainty ? el("p", { class: "muted small", text: `Uncertainty: ${x.uncertainty}` }) : null,
      el("p", { class: "muted small" }, j.ts ? "Saved analysis " : "Saved as ", el("a", { href: `/netmon/investigations/${j.id}`, text: `investigation #${j.id}` }),
        j.ts ? ` · ${fmtTime(j.ts)} by ${j.user} (${j.model}) · shown from storage, no new request` : "",
        u.output_tokens ? ` · ${fmtNum(u.input_tokens)} in / ${fmtNum(u.output_tokens)} out tokens` : "", j.ts ? "" : ` · ${ago(0)}`));
    $("aigo").textContent = "Re-analyze"; $("aigo").classList.remove("primary");
  }
})();
