import { invoke } from "@tauri-apps/api/core";

let statusEl: HTMLElement | null;

async function checkDaemon() {
  if (!statusEl) return;
  statusEl.textContent = "checking...";
  try {
    statusEl.textContent = await invoke("daemon_health", {});
  } catch (err) {
    statusEl.textContent = `daemon unreachable: ${err}`;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  statusEl = document.querySelector("#daemon-status");
  document
    .querySelector("#check-daemon")
    ?.addEventListener("click", checkDaemon);
});
