import { invoke } from "@tauri-apps/api/core";

let statusEl: HTMLElement | null;
let wipeStatusEl: HTMLElement | null;

async function checkDaemon() {
  if (!statusEl) return;
  statusEl.textContent = "checking...";
  try {
    statusEl.textContent = await invoke("daemon_health", {});
  } catch (err) {
    statusEl.textContent = `daemon unreachable: ${err}`;
  }
}

async function panicWipe() {
  if (!wipeStatusEl) return;
  const confirmed = window.confirm(
    "This irreversibly deletes all local keys and messages. Continue?",
  );
  if (!confirmed) return;

  wipeStatusEl.textContent = "wiping...";
  try {
    await invoke("panic_wipe_daemon", {});
    wipeStatusEl.textContent = "wiped. daemon has exited.";
  } catch (err) {
    wipeStatusEl.textContent = `wipe failed: ${err}`;
  }
}

// Screenshot/shoulder-surfing mitigation (SPEC.md §7): blur sensitive
// content whenever the window loses focus. This is a real, cross-platform
// mitigation, but it is not equivalent to true OS-level capture exclusion
// (Windows' SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE), which has no
// macOS/Linux equivalent for third-party apps) — that would need
// platform-specific native code and isn't implemented here.
function installBlurOnUnfocus() {
  window.addEventListener("blur", () => document.body.classList.add("bh-privacy-blur"));
  window.addEventListener("focus", () => document.body.classList.remove("bh-privacy-blur"));
}

window.addEventListener("DOMContentLoaded", () => {
  statusEl = document.querySelector("#daemon-status");
  wipeStatusEl = document.querySelector("#wipe-status");
  document
    .querySelector("#check-daemon")
    ?.addEventListener("click", checkDaemon);
  document.querySelector("#panic-wipe")?.addEventListener("click", panicWipe);
  installBlurOnUnfocus();
});
