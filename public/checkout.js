// The checkout page: copy buttons, the countdown, and checking every few seconds whether the bank
// confirmed the payment (then the page reloads with the result, and goes back to the shop if it asked).
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    const old = btn.textContent;
    btn.textContent = "¡Copiado!";
    setTimeout(() => (btn.textContent = old), 1500);
  } catch {
    window.prompt("Copia:", btn.dataset.copy);
  }
});

const meta = document.querySelector("[data-charge]");
const countdown = document.querySelector("[data-countdown]");
if (countdown) {
  const end = Date.now() + Number(countdown.dataset.countdown) * 1000;
  const tick = () => {
    const s = Math.max(0, Math.round((end - Date.now()) / 1000));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = String(s % 60).padStart(2, "0");
    countdown.textContent = h ? `${h} h ${String(m).padStart(2, "0")} min` : `${m}:${sec}`;
  };
  tick();
  setInterval(tick, 1000);
}

if (meta && meta.dataset.status === "pending") {
  let delay = 4000;
  const check = async () => {
    try {
      const res = await fetch(`/c/${meta.dataset.charge}/status`, { cache: "no-store" });
      if (res.ok) {
        const { status } = await res.json();
        if (status !== "pending") return location.reload();
      }
    } catch {}
    delay = Math.min(delay + 1000, 10000);
    setTimeout(check, document.hidden ? 15000 : delay);
  };
  setTimeout(check, delay);
}

const back = document.querySelector("[data-return]");
if (back && meta && meta.dataset.status === "paid" && sessionStorage.getItem(`pr-back-${meta.dataset.charge}`) !== "1") {
  try { sessionStorage.setItem(`pr-back-${meta.dataset.charge}`, "1"); } catch {}
  setTimeout(() => location.assign(back.href), 4000);
}
