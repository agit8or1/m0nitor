// Light / dark / system theme. Loaded in <head> so the saved choice applies before first paint (no wrong-theme flash).
"use strict";
(() => {
  const KEY = "nm.theme", root = document.documentElement;
  const get = () => { try { return localStorage.getItem(KEY) || "auto"; } catch (_) { return "auto"; } };
  const apply = (m) => { if (m === "light" || m === "dark") root.dataset.theme = m; else delete root.dataset.theme; };
  apply(get());
  const set = (m) => {
    try { localStorage.setItem(KEY, m); } catch (_) { /* private mode: applies to this page only */ }
    apply(m); window.dispatchEvent(new Event("nm-theme"));
  };
  // "System" follows the OS; re-render charts when the OS flips while that is selected
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (get() === "auto") window.dispatchEvent(new Event("nm-theme")); });
  document.addEventListener("DOMContentLoaded", () => document.querySelectorAll("select[data-theme-toggle]").forEach((s) => {
    s.value = get();
    s.addEventListener("change", () => set(s.value));
  }));
})();
