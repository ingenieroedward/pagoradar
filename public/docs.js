// Docs page: language tabs (remembered), copy buttons on code, and the table of contents following the scroll.
const LANG_KEY = "pr-docs-tab";
const saved = (() => { try { return localStorage.getItem(LANG_KEY); } catch { return null; } })();

for (const tabs of document.querySelectorAll(".tabs")) {
  const buttons = [...tabs.querySelectorAll("[role=tab]")];
  const panels = [...tabs.querySelectorAll(":scope > pre[data-tab]")];
  const show = (name) => {
    for (const b of buttons) b.setAttribute("aria-selected", String(b.dataset.tab === name));
    for (const p of panels) p.hidden = p.dataset.tab !== name;
  };
  show(buttons.some((b) => b.dataset.tab === saved) ? saved : buttons[0]?.dataset.tab);
  for (const b of buttons) {
    // Choosing a language switches every example on the page that has it.
    b.addEventListener("click", () => {
      try { localStorage.setItem(LANG_KEY, b.dataset.tab); } catch {}
      for (const same of document.querySelectorAll(`.tabs [role=tab][data-tab="${b.dataset.tab}"]`)) same.dispatchEvent(new CustomEvent("pick"));
    });
    b.addEventListener("pick", () => show(b.dataset.tab));
  }
}

for (const pre of document.querySelectorAll("pre")) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "Copiar";
  btn.addEventListener("click", async () => {
    const text = pre.querySelector("code")?.innerText ?? pre.innerText;
    try {
      await navigator.clipboard.writeText(text.replace(/^(\d{3} [A-Za-z ]+|HTTP\/1\.1 .+)\n/, ""));
      btn.textContent = "¡Copiado!";
    } catch {
      btn.textContent = "No se pudo";
    }
    setTimeout(() => (btn.textContent = "Copiar"), 1500);
  });
  pre.appendChild(btn);
}

// Table of contents: highlight the section on screen; on a phone, close it after choosing.
const links = new Map([...document.querySelectorAll(".toc nav a")].map((a) => [a.getAttribute("href").slice(1), a]));
const observer = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      for (const a of links.values()) a.classList.remove("active");
      links.get(e.target.id)?.classList.add("active");
    }
  },
  { rootMargin: "-80px 0px -70% 0px" },
);
for (const id of links.keys()) {
  const el = document.getElementById(id);
  if (el) observer.observe(el);
}
const toc = document.querySelector(".toc-mobile");
if (toc && window.matchMedia("(max-width: 999px)").matches) {
  toc.open = false;
  toc.addEventListener("click", (e) => { if (e.target.closest("a")) toc.open = false; });
}
