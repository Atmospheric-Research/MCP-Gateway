document.addEventListener("click", async (event) => {
  const copy = event.target.closest("[data-copy]");
  if (copy) {
    try {
      await navigator.clipboard.writeText(copy.dataset.copy);
      const label = copy.textContent;
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = label), 1200);
    } catch (_) {
      window.prompt("Copy this URL", copy.dataset.copy);
    }
    return;
  }

  const confirmBtn = event.target.closest("[data-confirm]");
  if (confirmBtn && !window.confirm(confirmBtn.dataset.confirm)) {
    event.preventDefault();
    return;
  }

  const test = event.target.closest("[data-test-url]");
  if (test) {
    const out = document.getElementById("test-result");
    test.disabled = true;
    out.hidden = false;
    delete out.dataset.state;
    out.textContent = "Starting server… the first run may take a while while uv installs dependencies.";
    try {
      const res = await fetch(test.dataset.testUrl, {
        method: "POST",
        headers: { "X-CSRF-Token": test.dataset.csrf },
      });
      const data = await res.json();
      const lines = [];
      if (data.ok) {
        lines.push(`OK — ${data.server_name} ${data.server_version || ""} (protocol ${data.protocol_version})`);
        lines.push(`${data.tools.length} tool(s):`);
        for (const t of data.tools) lines.push(`  • ${t.name}${t.description ? " — " + t.description.split("\n")[0] : ""}`);
      } else {
        lines.push(`FAILED — ${data.error}`);
      }
      if (data.log) lines.push("", "Recent stderr:", data.log);
      out.textContent = lines.join("\n");
      if (data.ok) renderTools(data.tools);
      out.dataset.state = data.ok ? "ok" : "fail";
    } catch (err) {
      out.textContent = `Request failed: ${err}`;
      out.dataset.state = "fail";
    } finally {
      test.disabled = false;
    }
  }
});

// Server edit page: test automatically when no tool list is cached yet (new or re-deployed server).
document.querySelector("[data-autotest]")?.click();

// Server form: show only the fields of the chosen kind; disabled fields are neither validated nor submitted.
document.addEventListener("change", (event) => {
  if (event.target.name !== "kind") return;
  for (const group of document.querySelectorAll("[data-kind]")) {
    const on = group.dataset.kind === event.target.value;
    group.hidden = !on;
    for (const input of group.querySelectorAll("input")) input.disabled = !on;
  }
});

// Server form: the zip drop zone names the picked file and lights up while something is dragged over it.
for (const zone of document.querySelectorAll(".dropzone")) {
  const input = zone.querySelector("input[type=file]");
  const name = zone.querySelector("[data-file-name]");
  const meta = zone.querySelector("[data-file-meta]");
  const initial = [name.innerHTML, meta.innerHTML];
  input.addEventListener("dragenter", () => zone.classList.add("dragging"));
  for (const type of ["dragleave", "drop"]) input.addEventListener(type, () => zone.classList.remove("dragging"));
  input.addEventListener("change", () => {
    const file = input.files[0];
    zone.classList.toggle("picked", Boolean(file));
    if (!file) [name.innerHTML, meta.innerHTML] = initial;
    else {
      name.textContent = file.name;
      meta.textContent = `${(file.size / 1024 / 1024).toFixed(file.size < 1048576 ? 2 : 1)} MB · click or drop to change`;
    }
  });
}

// Server form: one switch per tool from the last test; unchecked ones are saved as disabled.
function renderTools(tools) {
  const list = document.getElementById("tool-list");
  if (!list) return;
  document.getElementById("tool-list-empty")?.remove();
  const kept = new Set([...list.querySelectorAll("input[type=hidden]")].map((i) => i.value));
  for (const t of tools) {
    if (kept.has(t.name)) continue;
    const label = document.createElement("label");
    label.className = "check";
    const hidden = Object.assign(document.createElement("input"), { type: "hidden", name: "tools", value: t.name });
    const box = Object.assign(document.createElement("input"), { type: "checkbox", name: "tool_enabled", value: t.name, checked: t.enabled });
    box.setAttribute("role", "switch");
    const span = document.createElement("span");
    const code = document.createElement("code");
    code.textContent = t.name;
    span.append(code);
    if (t.description) {
      const small = document.createElement("small");
      small.textContent = t.description.split("\n")[0];
      span.append(small);
    }
    label.append(hidden, box, " ", span);
    list.append(label);
  }
}

// New server form: derive the slug from the name until the admin types a slug of their own.
const slugify = (name) =>
  name.replace(/ı/g, "i").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+/, "").slice(0, 64).replace(/-+$/, "");
document.addEventListener("input", (event) => {
  const slug = document.querySelector("input[data-auto-slug]");
  if (!slug) return;
  if (event.target === slug) slug.dataset.edited = slug.value ? "1" : "";
  else if (event.target.id === "name" && !slug.dataset.edited) slug.value = slugify(event.target.value);
});
