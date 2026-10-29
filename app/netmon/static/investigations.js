"use strict";
(() => {
  const { el, $ } = NM;
  const enabled = $("aienabled").value === "1";
  $("aiform").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const kind = $("aikind").value, target = $("aitarget").value.trim();
    const box = $("aipreview"); $("airesult").replaceChildren(); NM.state(box, "loading", "Building minimized evidence…");
    try {
      const d = await NM.get(`/netmon/api/ai/preview?${NM.qs({ kind, target })}`);
      const send = el("button", { class: "primary", disabled: !enabled || null, text: enabled ? `Send to OpenAI (${d.model})` : "Sending disabled — AI not configured" });
      box.replaceChildren(el("h3", { text: "Evidence preview — exactly what would be sent" }),
        el("p", { class: "muted small", text: `${d.chars.toLocaleString()} characters · sections: ${d.categories.join(", ")} · ${d.pseudonyms} internal identifiers pseudonymized. ${d.note}` }),
        el("pre", { class: "preview", text: JSON.stringify(d.body, null, 1) }), send);
      send.addEventListener("click", async () => {
        send.disabled = true; NM.state($("airesult"), "loading", "Waiting for the model…");
        const fd = new FormData(); fd.set("digest", d.digest); fd.set("csrf", $("csrf").value);
        const r = await fetch("/netmon/api/ai/send", { method: "POST", body: fd, credentials: "same-origin" });
        const j = await r.json();
        if (!j.ok) return NM.state($("airesult"), "error", j.error || "failed");
        location.href = `/netmon/investigations/${j.id}`;
      });
    } catch (e) { NM.state(box, "error", e.message); }
  });
  if ($("aitarget").value) $("aiform").requestSubmit();
})();
