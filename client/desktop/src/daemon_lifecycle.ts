// Thin wrapper around the Tauri commands in
// `src-tauri/src/daemon_lifecycle.rs` — the daemon used to be assumed
// already running (started separately); `boot()` in `main.ts` now calls
// `ensureDaemonRunning` itself, optionally supplying the database-unlock
// secret derived via `prf_unlock.ts` before the daemon (and its database)
// ever starts.

import { invoke } from "@tauri-apps/api/core";

/**
 * Ensures the daemon is reachable at `127.0.0.1:47853`, spawning it if
 * necessary. `dbPin` (when the active profile's database key is
 * PIN-protected) is passed through as the spawned process's
 * `BLACKHOLE_DB_PIN` environment variable — never logged, never sent
 * anywhere else.
 */
export async function ensureDaemonRunning(dbPin: string | null): Promise<void> {
  await invoke("ensure_daemon_running", { dbPin });
}

/** Stops the daemon this Tauri process spawned, if any. */
export async function stopDaemon(): Promise<void> {
  await invoke("stop_daemon");
}
