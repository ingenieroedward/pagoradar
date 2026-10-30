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

// Filter bars submit themselves: on choosing an option, and after a pause while typing in the search box.
// Empty fields are left out of the URL; the search box keeps the focus across the reload.
const filterForm = document.querySelector("form[data-autosubmit]");
if (filterForm) {
  const search = filterForm.querySelector("input[type=search]");
  const submit = (keepFocus) => {
    try { if (keepFocus) sessionStorage.setItem("pr-search-focus", "1"); } catch {}
    filterForm.requestSubmit();
  };
  filterForm.addEventListener("change", (e) => { if (e.target.matches("select")) submit(false); });
  filterForm.addEventListener("submit", () => {
    for (const el of filterForm.elements) if (el.name && !el.value) el.disabled = true;
  });
  if (search) {
    let timer;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => submit(true), 550); });
    search.addEventListener("search", () => { if (!search.value) submit(true); });
    try {
      if (sessionStorage.getItem("pr-search-focus") === "1") {
        sessionStorage.removeItem("pr-search-focus");
        search.focus();
        search.setSelectionRange(search.value.length, search.value.length);
      }
    } catch {}
  }
  // The date popover closes when tapping outside it.
  const pop = filterForm.querySelector("details.pop");
  if (pop) document.addEventListener("click", (e) => { if (pop.open && !pop.contains(e.target)) pop.open = false; });
}

// Passkeys: the browser's WebAuthn API speaks ArrayBuffers, the server base64url.
const toBytes = (b64) => Uint8Array.from(atob(b64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const postJson = async (url, csrf, body) => {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF": csrf }, body: JSON.stringify(body ?? {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Algo falló. Vuelve a intentarlo.");
  return data;
};
// The person closing the browser's dialog is not an error worth explaining.
const passkeyMessage = (err) => (err?.name === "NotAllowedError" || err?.name === "AbortError" ? "" : err?.name === "InvalidStateError" ? "Este dispositivo ya tiene una passkey tuya." : err?.message || "Algo falló.");

if (window.PublicKeyCredential) {
  const signIn = document.querySelector("[data-passkey-login]");
  if (signIn) {
    signIn.hidden = false;
    const note = signIn.querySelector("p[role=status]");
    const button = signIn.querySelector("button");
    button.addEventListener("click", async () => {
      button.disabled = true;
      note.hidden = true;
      try {
        const options = await postJson("/login/passkey/options", signIn.dataset.csrf);
        const cred = await navigator.credentials.get({ publicKey: { ...options, challenge: toBytes(options.challenge) } });
        const done = await postJson("/login/passkey", signIn.dataset.csrf, {
          id: cred.id,
          clientDataJSON: toB64(cred.response.clientDataJSON),
          authenticatorData: toB64(cred.response.authenticatorData),
          signature: toB64(cred.response.signature),
        });
        location.href = done.redirect;
      } catch (err) {
        note.textContent = passkeyMessage(err);
        note.hidden = !note.textContent;
        button.disabled = false;
      }
    });
  }

  const add = document.querySelector("[data-passkey-add]");
  if (add) {
    add.hidden = false;
    document.querySelector("[data-passkey-unsupported]")?.setAttribute("hidden", "");
    const error = add.querySelector("[role=alert]");
    const button = add.querySelector("button");
    button.addEventListener("click", async () => {
      button.disabled = true;
      error.hidden = true;
      try {
        const options = await postJson("/me/passkeys/options", add.dataset.csrf, { code: add.querySelector("[name=passkeyCode]").value });
        const cred = await navigator.credentials.create({
          publicKey: {
            ...options,
            challenge: toBytes(options.challenge),
            user: { ...options.user, id: toBytes(options.user.id) },
            excludeCredentials: options.excludeCredentials.map((c) => ({ ...c, id: toBytes(c.id) })),
          },
        });
        const done = await postJson("/me/passkeys/register", add.dataset.csrf, {
          id: cred.id,
          name: add.querySelector("[name=passkeyName]").value,
          clientDataJSON: toB64(cred.response.clientDataJSON),
          authenticatorData: toB64(cred.response.getAuthenticatorData()),
          publicKey: toB64(cred.response.getPublicKey()),
          alg: cred.response.getPublicKeyAlgorithm(),
          transports: cred.response.getTransports?.() ?? [],
        });
        location.href = done.redirect;
      } catch (err) {
        error.textContent = passkeyMessage(err);
        error.hidden = !error.textContent;
        button.disabled = false;
      }
    });
  }
}

// Installable app (PWA): the service worker only caches styles and icons, never pages with payment data.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}
