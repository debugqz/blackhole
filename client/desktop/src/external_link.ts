// Opening a URL outside the app.
//
// Neither `window.open` nor a bare `<a target="_blank">` does anything
// useful in this webview — there is no UI delegate to honor either — which
// is why the cosmetics-store checkout link and the link-preview card both
// silently did nothing when clicked. Loading a remote page *inside* the
// app's own webview would be worse than useless: it would share an origin
// with the UI that holds the daemon bridge (`daemon_call`).
//
// `tauri-plugin-opener` (registered in `src-tauri/src/lib.rs` and granted
// in `capabilities/default.json`, but until now never called from the
// frontend at all) hands the URL to the OS instead.

import { openUrl } from "@tauri-apps/plugin-opener";

/// Opens `url` in the user's real browser. http/https only: `openUrl` will
/// hand the OS whatever scheme it is given, and these URLs come from the
/// daemon or from a remote page's own markup, never from a constant.
export async function openExternal(url: string): Promise<void> {
  if (!/^https?:\/\//i.test(url)) {
    window.alert("Refusing to open a link that isn't http(s).");
    return;
  }
  try {
    await openUrl(url);
  } catch (err) {
    window.alert(`Could not open the link: ${err instanceof Error ? err.message : String(err)}`);
  }
}
