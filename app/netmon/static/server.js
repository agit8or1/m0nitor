"use strict";
(() => {
  const { el, $, fmtBytes, fmtBps, fmtNum, ago, fmtTime, sev } = NM;
  const ip = $("srvhead").dataset.ip; document.body.dataset.fixed = "host";
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/server?${NM.qs({ ip, host: "" })}`);
      NM.scopeDesc(d.scope);
      const s = d.summary;
      // the server's addresses with reverse DNS: LAN, then the public (1:1 NAT) address it is reached on
      $("srvhead").replaceChildren(el("div", { class: "srvaddrs" }, el("span", { class: "muted", text: "Addresses " }),
        ...d.addresses.map((x) => el("span", { class: "srvaddr" }, `${x.kind} `, el("code", { text: x.ip }),
          x.rdns ? el("span", { class: "muted", title: "reverse DNS (PTR)", text: ` (${x.rdns})` })
            : x.rdns === "" ? el("span", { class: "muted", title: "no reverse DNS (PTR) record", text: " (no rDNS)" }) : null))));
      NM.cards($("cards"), [
        { k: "Received (Internet → server)", sw: "--in", href: "#bw", v: fmtBytes(s.in_b), s: `avg ${fmtBps(s.in_avg_bps)} · flow-estimated` },
        { k: "Sent (server → Internet)", sw: "--out", href: "#bw", v: s.out_b ? fmtBytes(s.out_b) : "n/a", s: s.out_b ? `avg ${fmtBps(s.out_avg_bps)} · port-forward replies only` : "sent via shared NAT — not attributable from flows" },
        { k: "Remote addresses", href: NM.href("/netmon/connections", { host: ip }), v: fmtNum(s.peers), s: `${fmtNum(s.countries)} countries · ${fmtNum(s.flows)} flow records` },
        { k: "Open alerts", href: "#t-alerts", v: String(d.alerts.filter((a) => a.category !== "info").length), s: `${d.alerts.filter((a) => a.category === "info").length} informational` },
        { k: "Role / inventory", href: "#srvname", v: d.asset.role || "unknown", s: d.asset.sensitive ? "marked sensitive · edit below" : d.asset.notes || "edit name and role below" },
      ]);
      NM.lineChart($("bw"), d.flow_series.points, [{ key: "in_bps", cls: "in", label: "Received" }, { key: "out_bps", cls: "out", label: "Sent (attributable)" }],
        { unavailableBefore: d.collection.first });
      NM.legendInOut($("bwlegend"), "Received", "Sent (attributable)");
      const st = (k, v) => el("div", {}, el("span", { class: "k", text: k }), el("b", { text: v }));
      $("bwstats").replaceChildren(st("Received avg", fmtBps(s.in_avg_bps)), st("Received peak", fmtBps(d.flow_series.peak_in_bps)),
        st("Sent avg", s.out_b ? fmtBps(s.out_avg_bps) : "n/a"), st("Total transfer", fmtBytes(s.in_b + s.out_b)));
      $("bwnote").textContent = `Flow-estimated, ${d.flow_series.bucket} s buckets. Uploads this server makes through the shared outbound NAT address cannot be attributed to it from WAN flow records.`;
      NM.rank($("t-countries"), d.countries.slice(0, 10), { label: (c) => c.name, sub: (c) => `${fmtNum(c.flows)} flows`, link: (c) => NM.href(`/netmon/countries/${c.cc}`) });
      NM.rank($("t-orgs"), d.orgs, { label: (o) => o.asname || `AS${o.asn}`, sub: (o) => `AS${o.asn}` });
      const sv = $("t-services"); sv.replaceChildren(); const a = el("div"), b = el("div");
      sv.append(el("h3", { class: "grp", text: "Exposed (port forward)" }), a, el("h3", { class: "grp", text: "Used (port-based guess)" }), b);
      NM.rank(a, d.services.exposed.map((x) => ({ ...x, in_b: x.b, out_b: 0 })), { label: (x) => `${x.proto}/${x.port}${x.mgmt ? " ⚠ admin service" : ""}`, sub: (x) => `${fmtNum(x.clients)} clients`, empty: "No inbound service traffic" });
      NM.rank(b, d.services.outbound.map((x) => ({ ...x, in_b: x.b, out_b: 0 })), { label: (x) => `${x.svc || "port"} ${x.proto}/${x.port}`, sub: () => "guessed from port", empty: "None observed" });
      const nv = $("t-novel"); nv.replaceChildren();
      if (d.baseline_days < 3) nv.append(el("p", { class: "note", text: `Baseline has only ${d.baseline_days.toFixed(1)} days of data, so almost everything is "new". Treat this list as low confidence.` }));
      const items = d.novelty.slice(0, 24);
      if (!items.length) nv.append(el("div", { class: "state empty", text: "Nothing new versus the previous 14 days" }));
      else {
        for (const kind of ["country", "asn"]) { const xs = items.filter((n) => n.kind === kind); if (!xs.length) continue;
          nv.append(el("h3", { class: "grp", text: kind === "country" ? `New countries (${xs.length})` : `New networks (${xs.length})` }),
            el("div", { class: "chiplist" }, xs.map((n) => el("span", { class: "chip static", title: n.sub, text: n.label })))); }
        if (d.novelty.length > items.length) nv.append(el("p", { class: "note", text: `+ ${d.novelty.length - items.length} more` }));
      }
      NM.alertList($("t-alerts"), d.alerts, { empty: "No alerts for this server" });
      const ex = $("t-exposure"); ex.replaceChildren(
        el("h3", { class: "grp", text: "Reachable from the Internet (port forwards)" }),
        d.exposures.length ? el("ul", { class: "plain" }, d.exposures.map((x) => el("li", {}, el("code", { text: `${x.proto}/${x.ports}` }), ` via ${x.public_fw ? `${x.public_fw} ` : ""}${x.public_ip}`,
          x.rdns ? el("span", { class: "muted", title: "reverse DNS (PTR)", text: ` (${x.rdns})` }) : null))) : el("p", { class: "muted", text: "No port forwards" }),
        el("h3", { class: "grp", text: "AI analysis" }),
        d.ai_enabled ? el("a", { class: "btn", href: NM.href("/netmon/investigations", { kind: "server", target: ip }), text: "Analyze with AI…" })
          : el("p", { class: "muted" }, "AI analysis not configured — ", el("a", { href: "/netmon/investigations", text: "setup" }), ". You can still preview the evidence."));
      NM.convTable($("t-conv"), d.conversations.rows, { empty: "No conversations for this server in this scope" });
    } catch (e) { NM.state($("cards"), "error", e.message); }
  }
  NM.onScope(load); load(); NM.every(load, 60000);
})();
