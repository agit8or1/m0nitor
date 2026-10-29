"use strict";
(() => {
  const { el, $, fmtNum, fmtTime, sev } = NM;
  const sv = (n) => ({ 1: "high", 2: "medium" }[n] || "low");
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/ids?${NM.qs()}`);
      NM.scopeDesc(d.scope);
      $("idsstate").replaceChildren(d.sources.ids.last ? "" : el("div", { class: "banner warn" }, el("b", { text: "Suricata IDS is not connected. " }),
        "No IDS alerts have been received — this is not the same as “no attacks”. ", el("a", { href: "/netmon/settings/integrations", text: "Enable Suricata (alert-only) →" })));
      NM.table($("t-sigs"), [{ label: "Severity", get: (r) => sev(sv(+r.severity)) }, { label: "Signature", get: (r) => el("span", {}, r.signature, el("div", { class: "sub", text: `SID ${r.sig_id} · ${r.category}` })) },
        { label: "Hits", cls: "num", get: (r) => fmtNum(r.hits) }, { label: "Sources", cls: "num", get: (r) => fmtNum(r.sources) },
        { label: "Action", get: (r) => r.actions.join(", ") }, { label: "Last", cls: "num", get: (r) => fmtTime(r.last, true) }], d.signatures, { empty: "No IDS alerts in this window" });
      NM.table($("t-recent"), [{ label: "Time", cls: "num", get: (r) => fmtTime(r.ms / 1000, true) }, { label: "Severity", get: (r) => sev(sv(+r.severity)) },
        { label: "Signature", get: (r) => r.signature }, { label: "Source", get: (r) => el("span", {}, NM.ipCell(r.src, r.src_name), el("span", { class: "muted small", text: ` :${r.sport}` })) },
        { label: "Destination", get: (r) => `${r.dst}:${r.dport}` }, { label: "Proto", get: (r) => r.proto }, { label: "Action", get: (r) => r.action }], d.recent, { empty: "No IDS alerts in this window" });
    } catch (e) { NM.state($("t-sigs"), "error", e.message); }
  }
  NM.onScope(load); load(); NM.every(load, 60000);
})();
