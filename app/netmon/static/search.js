"use strict";
(() => {
  const { el, $ } = NM;
  const box = $("results"), q = box.dataset.q; const inp = $("q"); if (inp) inp.value = q;
  NM.get(`/netmon/api/search?q=${encodeURIComponent(q)}`).then((d) => {
    if (!d.results.length) return NM.state(box, "empty", "Nothing matched. Try a server name, IP address, country, port number or organization.");
    const link = (r) => NM.href(r.href.split("?")[0], Object.fromEntries(new URLSearchParams(r.href.split("?")[1] || "")));
    NM.table(box, [{ label: "Type", get: (r) => r.type },
      { label: "Match", get: (r) => r.ip ? NM.ipCell(r.ip, r.name, link(r)) : el("a", { href: link(r), text: r.label }) },
      { label: "", get: (r) => el("span", { class: "muted", text: r.sub }) }], d.results);
  }).catch((e) => NM.state(box, "error", e.message));
})();
