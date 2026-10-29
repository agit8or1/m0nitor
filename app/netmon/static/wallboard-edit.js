"use strict";
(() => {
  const { el, $ } = NM;
  let lay = null, def = null;
  const opts = (vals, cur) => vals.map((v) => el("option", { value: v, selected: String(v) === String(cur) || null, text: v }));
  function tiles() {
    const box = $("wbtiles"); box.replaceChildren();
    lay.widgets.forEach((w, i) => {
      const cat = def.catalog[w.type];
      const mv = (d) => () => { const j = i + d; if (j < 0 || j >= lay.widgets.length) return; [lay.widgets[i], lay.widgets[j]] = [lay.widgets[j], lay.widgets[i]]; changed(); };
      const wsel = el("select", { "aria-label": "Width" }, opts([2, 3, 4, 6, 8, 9, 12], w.w)); wsel.addEventListener("change", () => { w.w = +wsel.value; changed(); });
      const hsel = el("select", { "aria-label": "Height" }, opts([1, 2, 3, 4], w.h)); hsel.addEventListener("change", () => { w.h = +hsel.value; changed(); });
      const tin = el("input", { value: w.title || "", placeholder: cat.label, maxlength: 60, "aria-label": "Title" }); tin.addEventListener("change", () => { w.title = tin.value; changed(); });
      const up = el("button", { text: "↑", title: "Move up" }), dn = el("button", { text: "↓", title: "Move down" }), rm = el("button", { text: "Remove" });
      up.addEventListener("click", mv(-1)); dn.addEventListener("click", mv(1)); rm.addEventListener("click", () => { lay.widgets.splice(i, 1); changed(); });
      box.append(el("div", { class: "tilerow" }, el("b", { text: `${i + 1}. ${cat.label}` }), el("span", { class: "muted small", text: cat.desc }),
        el("label", { class: "inl" }, "width", wsel), el("label", { class: "inl" }, "height", hsel), el("label", { class: "inl" }, "title", tin), up, dn, rm));
    });
    if (!lay.widgets.length) box.append(el("p", { class: "state empty", text: "No tiles yet — add one above." }));
  }
  let pv; function changed() { tiles(); clearTimeout(pv); pv = setTimeout(() => WB.render(JSON.parse(JSON.stringify(lay))), 300); $("wbmsg").textContent = "Unsaved changes"; }
  WB.ready.then((d) => {
    def = d; lay = JSON.parse(JSON.stringify(d.layout));
    $("wbname").value = d.name; $("wbrange").value = lay.range; $("wbrefresh").value = lay.refresh;
    $("wbsite").append(...d.sites.map((s) => el("option", { value: s.id, text: s.name }))); $("wbsite").value = lay.site || "all";
    $("wbadd").append(...Object.entries(d.catalog).map(([k, v]) => el("option", { value: k, text: v.label })));
    for (const id of ["wbrange", "wbsite", "wbrefresh"]) $(id).addEventListener("change", () => { lay.range = $("wbrange").value; lay.site = $("wbsite").value; lay.refresh = +$("wbrefresh").value || 30; changed(); });
    $("wbaddbtn").addEventListener("click", () => { const t = $("wbadd").value, c = d.catalog[t]; lay.widgets.push({ type: t, w: c.w, h: c.h, title: "" }); changed(); });
    $("wbsave").addEventListener("click", async () => {
      const r = await fetch(`/netmon/api/wallboards/${d.id}`, { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF": $("csrf").value }, body: JSON.stringify({ name: $("wbname").value, layout: lay }) });
      $("wbmsg").textContent = r.ok ? "Saved." : `Save failed (HTTP ${r.status})`;
      if (r.ok) setTimeout(() => { location.href = `/netmon/wallboards/${d.id}`; }, 400);
    });
    tiles(); WB.render(JSON.parse(JSON.stringify(lay)));
  });
})();
