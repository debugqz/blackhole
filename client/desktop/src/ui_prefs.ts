// Client-only UI preferences — pure localStorage, no daemon involvement.
// Deliberately NOT namespaced per-profile (like link_preview.ts's own
// setting) since these are about how this device's screen looks/behaves,
// not about any identity. Some of these (dnd, "coming soon" language,
// bandwidth) are persisted even though nothing reads them to change
// behavior yet — see each one's own doc comment for what's real today.

const PREFIX = "bh-ui-pref:";

function getBool(key: string, fallback: boolean): boolean {
  try {
    const raw = window.localStorage.getItem(PREFIX + key);
    return raw === null ? fallback : raw === "1";
  } catch {
    return fallback;
  }
}
function setBool(key: string, value: boolean): void {
  try {
    window.localStorage.setItem(PREFIX + key, value ? "1" : "0");
  } catch {
    // best-effort — a private-browsing-style storage block just means the
    // preference resets next launch, not a functional failure.
  }
}
function getString(key: string, fallback: string): string {
  try {
    return window.localStorage.getItem(PREFIX + key) ?? fallback;
  } catch {
    return fallback;
  }
}
function setString(key: string, value: string): void {
  try {
    window.localStorage.setItem(PREFIX + key, value);
  } catch {
    // best-effort, see getBool.
  }
}

export type Density = "compact" | "comfortable" | "spacious";
export type FontSize = "small" | "medium" | "large";

export function getDensity(): Density {
  const v = getString("density", "comfortable");
  return v === "compact" || v === "spacious" ? v : "comfortable";
}
export function setDensity(value: Density): void {
  setString("density", value);
}

export function getFontSize(): FontSize {
  const v = getString("font-size", "medium");
  return v === "small" || v === "large" ? v : "medium";
}
export function setFontSize(value: FontSize): void {
  setString("font-size", value);
}

export function isReduceMotionEnabled(): boolean {
  return getBool("reduce-motion", false);
}
export function setReduceMotionEnabled(value: boolean): void {
  setBool("reduce-motion", value);
}

export function isHighContrastEnabled(): boolean {
  return getBool("high-contrast", false);
}
export function setHighContrastEnabled(value: boolean): void {
  setBool("high-contrast", value);
}

export function isAlwaysUnderlineLinksEnabled(): boolean {
  return getBool("underline-links", false);
}
export function setAlwaysUnderlineLinksEnabled(value: boolean): void {
  setBool("underline-links", value);
}

/// Real: an attached image is re-encoded through a <canvas> before upload
/// when this is on, which genuinely discards EXIF (location, camera
/// model, capture time) since the re-encoded output never carries the
/// original file's metadata segments. See main.ts's attachment-input
/// handler.
export function isStripExifEnabled(): boolean {
  return getBool("strip-exif", true);
}
export function setStripExifEnabled(value: boolean): void {
  setBool("strip-exif", value);
}

const DEFAULT_QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢"];

export function getQuickReactions(): string[] {
  const raw = getString("quick-reactions", "");
  if (!raw) return DEFAULT_QUICK_REACTIONS;
  const parsed = Array.from(raw.trim()).filter((ch) => ch.trim().length > 0);
  return parsed.length > 0 ? parsed.slice(0, 8) : DEFAULT_QUICK_REACTIONS;
}
export function setQuickReactions(emojis: string[]): void {
  setString("quick-reactions", emojis.join(""));
}

/// NOT wired to anything yet — this app doesn't play sounds or raise OS
/// notifications for new messages at all today, so there's nothing for a
/// quiet-hours window to actually silence. Persisted so a future
/// notification feature can read it without a settings-migration step,
/// but toggling it has no visible effect right now. The settings UI says
/// so explicitly rather than pretending otherwise.
export interface DndWindow {
  enabled: boolean;
  start: string;
  end: string;
}
export function getDndWindow(): DndWindow {
  return {
    enabled: getBool("dnd-enabled", false),
    start: getString("dnd-start", "22:00"),
    end: getString("dnd-end", "08:00"),
  };
}
export function setDndWindow(win: DndWindow): void {
  setBool("dnd-enabled", win.enabled);
  setString("dnd-start", win.start);
  setString("dnd-end", win.end);
}

export function applyUiPrefs(root: HTMLElement): void {
  root.dataset.density = getDensity();
  root.dataset.fontSize = getFontSize();
  root.classList.toggle("reduce-motion", isReduceMotionEnabled());
  root.classList.toggle("high-contrast", isHighContrastEnabled());
  root.classList.toggle("underline-links", isAlwaysUnderlineLinksEnabled());
}
