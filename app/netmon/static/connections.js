"use strict";
(() => {
  const { $, el } = NM;
  const url = new URLSearchParams(location.search);
  let page = 1, sort = "bytes", dir = ["in", "out", "unknown"].includes(url.get("dir")) ? url.get("dir") : "", proto = url.get("proto") || "";
  const seg = $("convsort"), dseg = $("convdir"), f = $("convf");
  const mark = () => { seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.v === sort));
    dseg.querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b.dataset.v === dir); b.setAttribute("aria-pressed", b.dataset.v === dir); }); };
  // the page-only filters (direction, protocol) live in the URL beside the shared scope so links and reloads keep them
  const keepUrl = () => { const q = new URLSearchParams(NM.qs({ dir, proto })); history.replaceState(null, "", location.pathname + (q.toString() ? "?" + q : "")); };
  const fill = () => { f.proto.value = proto; for (const k of ["port", "host", "rip"]) f[k].value = NM.scope[k] || "";
    const chips = [];
    if (NM.scope.cc) chips.push(["cc", `Country ${NM.scope.cc}`]);
    if (NM.scope.asn) chips.push(["asn", `AS${NM.scope.asn}`]);
    $("convchips").replaceChildren(...chips.map(([k, t]) => { const b = el("button", { type: "button", class: "chip", title: `Remove ${t} filter`, text: `${t} ✕` });
      b.addEventListener("click", () => NM.setScope({ [k]: "" })); return b; })); };
  seg.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; sort = b.dataset.v; page = 1; mark(); load(); });
  dseg.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; dir = b.dataset.v; page = 1; mark(); keepUrl(); load(); });
  f.addEventListener("submit", (ev) => { ev.preventDefault(); proto = f.proto.value; page = 1;
    NM.setScope({ port: f.port.value.trim(), host: f.host.value.trim(), rip: f.rip.value.trim() }); keepUrl(); });
  f.proto.addEventListener("change", () => { proto = f.proto.value; page = 1; keepUrl(); load(); });
  $("convclear").addEventListener("click", () => { dir = ""; proto = ""; page = 1; mark(); NM.setScope({ port: "", host: "", rip: "", cc: "", asn: "" }); keepUrl(); });
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/connections?${NM.qs({ page, sort, dir, proto })}`);
      NM.scopeDesc(d.scope); $("convnote").textContent = `${d.total.toLocaleString()} conversation(s) · ${d.note}`;
      NM.convTable($("conv"), d.rows, { empty: "No conversations match these filters" });
      NM.pager($("pager"), d.page, d.per, d.total, (p) => { page = p; load(); });
    } catch (e) { NM.state($("conv"), "error", e.message); }
  }
  mark(); fill(); NM.onScope(() => { page = 1; fill(); keepUrl(); load(); }); load(); NM.every(load, 60000);
})();
