// Small progressive enhancements for the admin panel (it works without JavaScript too).
document.addEventListener("click", async (e) => {
  const copy = e.target.closest("[data-copy]");
  if (copy) {
    try {
      await navigator.clipboard.writeText(copy.dataset.copy);
      const old = copy.textContent;
      copy.textContent = "¡Copiado!";
      setTimeout(() => (copy.textContent = old), 1500);
    } catch {
      window.prompt("Copia el texto:", copy.dataset.copy);
    }
  }
});

document.addEventListener("submit", (e) => {
  const form = e.target.closest("form[data-confirm]");
  if (form && !window.confirm(form.dataset.confirm)) e.preventDefault();
});

// Pages that wait for something (a Gmail code, the first notice) refresh themselves.
const refresh = document.querySelector("[data-autorefresh]");
if (refresh) setTimeout(() => location.reload(), Number(refresh.dataset.autorefresh) * 1000);

// "Probar un aviso (.eml)": sends the file as it is and shows what pagoradar would read.
const checker = document.querySelector("[data-eml-check]");
if (checker) {
  const input = checker.querySelector("input[type=file]");
  const out = checker.querySelector("pre");
  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;
    out.hidden = false;
    out.textContent = "Revisando…";
    try {
      const res = await fetch(checker.dataset.emlCheck, {
        method: "POST",
        headers: { "Content-Type": "message/rfc822", "X-CSRF": checker.dataset.csrf },
        body: await file.arrayBuffer(),
      });
      out.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (err) {
      out.textContent = "No se pudo revisar: " + err.message;
    }
    input.value = "";
  });
}

// Drag a .eml onto the drop zone.
const drop = document.querySelector(".drop");
if (drop) {
  const input = drop.querySelector("input[type=file]");
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("over")));
  for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    if (!e.dataTransfer?.files?.length) return;
    input.files = e.dataTransfer.files;
    input.dispatchEvent(new Event("change"));
  });
}

// The "Más" menu closes when tapping outside it.
const more = document.querySelector("details.more");
if (more) document.addEventListener("click", (e) => { if (more.open && !more.contains(e.target)) more.open = false; });
