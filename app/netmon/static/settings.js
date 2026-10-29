"use strict";
(() => {
  // Firewalls page: LAN fields only matter for OPNsense (flows split by interface)
  document.querySelectorAll("form.fwform").forEach((f) => {
    const v = f.querySelector(".fw-vendor"); if (!v) return;
    const show = () => f.querySelectorAll(".fw-routed").forEach((l) => { l.hidden = v.value !== "opnsense"; });
    v.addEventListener("change", show); show();
  });
  const capNodes = document.querySelectorAll("[data-capacity]");
  if (capNodes.length && typeof NM !== "undefined") NM.onLive((L) => capNodes.forEach((n) =>
    NM.meters(n, (L.capacity || []).filter((x) => x.id === n.dataset.capacity), { compact: true })));
  const t = document.getElementById("chtype");
  if (t) {
    const show = () => document.querySelectorAll("fieldset.chfields").forEach((f) => {
      const on = f.dataset.type === t.value; f.hidden = !on; f.querySelectorAll("input").forEach((i) => { i.disabled = !on; }); });
    t.addEventListener("change", show); show();
  }
  const mw = document.getElementById("mwform");
  if (mw) mw.addEventListener("submit", (ev) => {
    const s = Date.parse(mw.start_l.value) / 1000, e = Date.parse(mw.end_l.value) / 1000;
    if (!(s < e)) { ev.preventDefault(); mw.querySelector("button").textContent = "End must be after start"; return; }
    mw.start.value = String(s); mw.end.value = String(e);
  });
  document.querySelectorAll("form.confirm").forEach((f) => f.addEventListener("submit", (ev) => {
    const b = f.querySelector("button"); if (b.dataset.armed) return; ev.preventDefault(); b.dataset.armed = "1"; b.textContent = "Click again to confirm";
    setTimeout(() => { delete b.dataset.armed; b.textContent = "Delete"; }, 4000); }));
  document.querySelectorAll("div.geocode").forEach((g) => {
    const form = g.closest("form"), q = g.querySelector(".geo-q"), btn = g.querySelector(".geo-go"), out = g.querySelector(".geo-res");
    const msg = (t) => { out.replaceChildren(Object.assign(document.createElement("p"), { className: "muted small", textContent: t })); };
    const go = async () => {
      if (q.value.trim().length < 3) { msg("Type at least 3 characters."); return; }
      btn.disabled = true; msg("Looking up…");
      try {
        const body = new URLSearchParams({ q: q.value, csrf: form.csrf.value });
        const r = await fetch("/netmon/api/geocode", { method: "POST", body, credentials: "same-origin" });
        const d = await r.json();
        if (!d.ok) { msg(d.error || "Lookup failed."); return; }
        if (!d.results.length) { msg("No matches. Try adding city or country."); return; }
        const ul = document.createElement("ul"); ul.className = "geo-list";
        for (const x of d.results) {
          const b = document.createElement("button"); b.type = "button"; b.className = "geo-pick";
          b.textContent = `${x.name} (${x.lat.toFixed(4)}, ${x.lon.toFixed(4)})`;
          b.addEventListener("click", () => {
            form.lat.value = x.lat.toFixed(5); form.lon.value = x.lon.toFixed(5);
            if (!form.label.value && x.label) form.label.value = x.label;
            if (x.country && [...form.country.options].some((o) => o.value === x.country)) form.country.value = x.country;
            msg(`Filled ${x.lat.toFixed(4)}, ${x.lon.toFixed(4)}. Click Save to apply.`);
          });
          const li = document.createElement("li"); li.append(b); ul.append(li);
        }
        out.replaceChildren(ul);
      } catch (_) { msg("Lookup failed. Enter coordinates manually."); } finally { btn.disabled = false; }
    };
    btn.addEventListener("click", go);
    q.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); go(); } });
  });
})();
