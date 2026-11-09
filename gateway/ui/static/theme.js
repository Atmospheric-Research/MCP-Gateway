// Loaded in <head> so a saved theme applies before first paint; no saved choice means follow the OS.
const root = document.documentElement;
try { const saved = localStorage.getItem("theme"); if (saved === "light" || saved === "dark") root.dataset.theme = saved; } catch (_) {}
document.addEventListener("click", (event) => {
  if (!event.target.closest("[data-theme-toggle]")) return;
  const dark = (root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch (_) {}
});
