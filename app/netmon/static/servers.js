"use strict";
(() => {
  const { el, $, fmtBytes, fmtBps, fmtNum, fmtTime } = NM;
  let page = 1, sort = "total";
  async function load() {
    const tb = document.querySelector("#srv tbody");
    try {
      const d = await NM.get(`/netmon/api/servers?${NM.qs({ page, sort })}`);
      NM.scopeDesc(d.scope);
      tb.replaceChildren(...d.rows.map((h) => el("tr", {},
        el("td", {}, el("a", { href: NM.href(`/netmon/servers/${h.ip}`), text: h.name || h.ip }), h.sensitive ? el("span", { class: "tag", text: "sensitive" }) : null,
          el("div", { class: "sub", text: h.role })),
        el("td", {}, el("code", { text: h.ip })),
        el("td", { class: "num", text: fmtBps(h.in_bps) }),
        el("td", { class: "num", title: h.tx ? "port-forward replies attributable to this server" : "outbound via shared NAT is not attributable", text: h.tx ? fmtBps(h.out_bps) : "n/a" }),
        el("td", { class: "num" }, fmtBytes(h.rx + h.tx), el("div", { class: "sub", text: `↓ ${fmtBytes(h.rx)} ↑ ${h.tx ? fmtBytes(h.tx) : "n/a"}` })),
        el("td", {}, h.top_remote ? el("a", { href: NM.href("/netmon/connections", { rip: h.top_remote }), text: h.top_remote }) : "—"),
        el("td", { class: "num", text: fmtNum(h.countries) }),
        el("td", { class: "num" }, h.alerts ? el("a", { href: "/netmon/security", class: "sev s-serious", text: `◆ ${h.alerts}` }) : "0"),
        el("td", { class: "num", text: h.last ? fmtTime(h.last, true) : "—" }))));
      if (!d.rows.length) tb.replaceChildren(el("tr", {}, el("td", { colspan: 9, class: "state empty", text: "No servers in this scope" })));
      NM.pager($("pager"), d.page, d.per, d.total, (p) => { page = p; load(); });
      $("srvnote").textContent = d.unattributed_nat_tx ? `${fmtBytes(d.unattributed_nat_tx)} uploaded via shared NAT (unattributed)` : "";
    } catch (e) { tb.replaceChildren(el("tr", {}, el("td", { colspan: 9, class: "state error", text: e.message }))); }
  }
  document.querySelectorAll("#srv th[data-sort]").forEach((th) => { th.classList.add("clickable"); th.addEventListener("click", () => {
    sort = th.dataset.sort === "name" ? "total" : th.dataset.sort; page = 1;
    document.querySelectorAll("#srv th").forEach((x) => x.classList.toggle("sorted", x === th)); load(); }); });
  NM.onScope(() => { page = 1; load(); }); load(); NM.every(load, 60000);
})();
