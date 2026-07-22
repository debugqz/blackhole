// Client-side, opt-in Open Graph link previews (title/description/image
// cards for URLs pasted into chat).
//
// This module is entirely self-contained on the client: it never asks the
// daemon to fetch anything (`invoke("fetch_link_preview", ...)` calls a
// Tauri command — see `src-tauri/src/link_preview.rs` — that talks
// straight to the linked site, bypassing the daemon and the P2P network
// stack completely). That's deliberate: SPEC.md's zero-knowledge design
// means the operator/daemon side should have no idea a preview was even
// requested.
//
// It is also OFF by default. Fetching a link preview means *your* device
// makes an outbound HTTP request straight to whatever site is linked, at
// the moment you (or a contact) sends that link — which reveals your IP
// address, roughly when you're active, and which link you're looking at,
// to that site. That's a real, unavoidable privacy tradeoff for a feature
// like this (there is no way to render a title/image/description for a
// URL without asking that URL's server for them), so it's surfaced
// explicitly rather than buried in a quiet default-on toggle. See
// `LINK_PREVIEW_SETTING_COPY` below for the exact wording shown in the UI.

import { invoke } from "@tauri-apps/api/core";

const SETTING_KEY = "bh_link_previews_enabled";

// Exact copy shown next to the settings toggle (index.html /
// renderLinkPreviewSettings in main.ts) and reused here so the tradeoff is
// stated identically everywhere it's surfaced, not paraphrased differently
// in different corners of the UI.
export const LINK_PREVIEW_SETTING_COPY = {
  label: "Show link previews",
  warning:
    "Off by default. Turning this on means that when a message contains a link, " +
    "your device will connect directly to that link's website to fetch its " +
    "title, description, and image — revealing your IP address and that you " +
    "opened this link to that site's operator, outside Blackhole's control. " +
    "This request never goes through Blackhole's daemon or network stack, " +
    "but it is not anonymized or proxied either.",
};

// ---------------- opt-in setting ----------------

export function isLinkPreviewsEnabled(): boolean {
  try {
    return window.localStorage.getItem(SETTING_KEY) === "1";
  } catch {
    // Storage can be unavailable (e.g. locked down webview prefs) — fail
    // closed, since this gates an involuntary network request.
    return false;
  }
}

export function setLinkPreviewsEnabled(enabled: boolean): void {
  try {
    window.localStorage.setItem(SETTING_KEY, enabled ? "1" : "0");
  } catch {
    // Best-effort; the in-memory default (off) still applies this session.
  }
}

// ---------------- URL detection ----------------

// Conservative, not a full URL parser: only recognizes explicit http(s)://
// links, and trims off characters that are almost always trailing
// punctuation rather than part of the URL (closing parens/brackets,
// sentence punctuation, trailing quotes). False negatives (missing an
// unusual URL) are fine here; false positives that mangle a real link are
// worse, so this errs toward being strict.
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const TRAILING_PUNCTUATION = /[).,!?;:'"`\]]+$/;

export function findFirstUrl(text: string): string | null {
  URL_PATTERN.lastIndex = 0;
  const match = URL_PATTERN.exec(text);
  if (!match) return null;
  return trimTrailingPunctuation(match[0]);
}

export function findAllUrls(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(URL_PATTERN)) {
    found.push(trimTrailingPunctuation(match[0]));
  }
  return found;
}

function trimTrailingPunctuation(url: string): string {
  let trimmed = url;
  // Only strip a trailing `)` if it isn't balancing a `(` earlier in the
  // URL (common in e.g. Wikipedia links) — otherwise strip greedily.
  while (TRAILING_PUNCTUATION.test(trimmed)) {
    const last = trimmed[trimmed.length - 1];
    if (last === ")" && countChar(trimmed, "(") >= countChar(trimmed, ")")) {
      break;
    }
    trimmed = trimmed.slice(0, -1);
  }
  return trimmed;
}

function countChar(value: string, ch: string): number {
  let count = 0;
  for (const c of value) if (c === ch) count += 1;
  return count;
}

// ---------------- fetch + parse ----------------

export interface LinkPreviewData {
  url: string;
  finalUrl: string;
  title: string | null;
  description: string | null;
  image: string | null;
  siteName: string | null;
}

interface FetchLinkPreviewResponse {
  final_url: string;
  content_type: string;
  html: string;
}

// In-memory cache keyed by the original URL string. `undefined` = never
// requested; `null` = fetched but nothing renderable came back (or the
// fetch failed) — cached too, so a link with no OG tags or an unreachable
// host isn't re-fetched on every render.
const cache = new Map<string, LinkPreviewData | null>();
const inFlight = new Map<string, Promise<LinkPreviewData | null>>();

export function getCachedLinkPreview(url: string): LinkPreviewData | null | undefined {
  return cache.get(url);
}

export function clearLinkPreviewCache(): void {
  cache.clear();
  inFlight.clear();
}

/// Fetches (or returns the cached result for) a link preview. Callers must
/// check `isLinkPreviewsEnabled()` themselves before calling this — this
/// function does not gate itself on the setting, so it stays a plain,
/// testable "given a URL, get a preview" primitive.
export async function fetchLinkPreview(url: string): Promise<LinkPreviewData | null> {
  const cached = cache.get(url);
  if (cached !== undefined) return cached;

  const pending = inFlight.get(url);
  if (pending) return pending;

  const promise = (async (): Promise<LinkPreviewData | null> => {
    try {
      const response = await invoke<FetchLinkPreviewResponse>("fetch_link_preview", { url });
      if (!response.content_type.toLowerCase().includes("html")) {
        cache.set(url, null);
        return null;
      }
      const data = parseOpenGraph(response.html, response.final_url, url);
      cache.set(url, data);
      return data;
    } catch {
      // Unreachable host, timeout, blocked address, non-2xx status, etc. —
      // the message still renders fine without a preview card.
      cache.set(url, null);
      return null;
    } finally {
      inFlight.delete(url);
    }
  })();

  inFlight.set(url, promise);
  return promise;
}

// A light regex scan, not a real HTML parser: good enough for `<meta>` and
// `<title>` tags, which is all a link preview needs, without pulling in a
// full DOM/HTML parsing dependency for it.
const META_TAG_PATTERN = /<meta\b[^>]*>/gi;
const ATTR_PATTERN = /([a-zA-Z][a-zA-Z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const TITLE_TAG_PATTERN = /<title[^>]*>([\s\S]*?)<\/title>/i;

function parseOpenGraph(html: string, finalUrl: string, originalUrl: string): LinkPreviewData | null {
  const og = new Map<string, string>();

  for (const tagMatch of html.matchAll(META_TAG_PATTERN)) {
    const tag = tagMatch[0];
    let property: string | null = null;
    let content: string | null = null;
    ATTR_PATTERN.lastIndex = 0;
    let attrMatch: RegExpExecArray | null;
    while ((attrMatch = ATTR_PATTERN.exec(tag))) {
      const name = attrMatch[1].toLowerCase();
      const value = attrMatch[2] ?? attrMatch[3] ?? "";
      if (name === "property" || name === "name") property = value.toLowerCase();
      if (name === "content") content = value;
    }
    if (property && content !== null && !og.has(property)) {
      og.set(property, decodeHtmlEntities(content));
    }
  }

  const title = og.get("og:title") ?? extractTitleTag(html) ?? null;
  const description = og.get("og:description") ?? og.get("description") ?? null;
  const siteName = og.get("og:site_name") ?? null;
  const rawImage = og.get("og:image") ?? og.get("og:image:url") ?? null;
  const image = rawImage ? resolveUrl(rawImage, finalUrl) : null;

  if (!title && !description && !image) return null;

  return {
    url: originalUrl,
    finalUrl,
    title: truncate(title, 200),
    description: truncate(description, 300),
    image,
    siteName: truncate(siteName, 80),
  };
}

function extractTitleTag(html: string): string | null {
  const match = TITLE_TAG_PATTERN.exec(html);
  if (!match) return null;
  const text = decodeHtmlEntities(match[1]).replace(/\s+/g, " ").trim();
  return text || null;
}

function resolveUrl(candidate: string, base: string): string | null {
  try {
    return new URL(candidate, base).toString();
  } catch {
    return null;
  }
}

function truncate(value: string | null, max: number): string | null {
  if (!value) return null;
  const trimmed = value.replace(/\s+/g, " ").trim();
  if (!trimmed) return null;
  return trimmed.length > max ? `${trimmed.slice(0, max - 1)}…` : trimmed;
}

const HTML_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  "#39": "'",
};

function decodeHtmlEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, entity: string) => {
    if (entity[0] === "#") {
      const codePoint = entity[1] === "x" || entity[1] === "X" ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
      if (Number.isFinite(codePoint)) {
        try {
          return String.fromCodePoint(codePoint);
        } catch {
          return whole;
        }
      }
      return whole;
    }
    return HTML_ENTITIES[entity] ?? whole;
  });
}

// ---------------- rendering ----------------

// Renders a preview card for a link, or `null` if previews are off, the
// text has no URL, or nothing came back for it (the caller should just
// render nothing in that case rather than an empty box).
export async function renderLinkPreviewCard(messageText: string): Promise<HTMLElement | null> {
  if (!isLinkPreviewsEnabled()) return null;
  const url = findFirstUrl(messageText);
  if (!url) return null;
  const data = await fetchLinkPreview(url);
  if (!data) return null;
  return buildLinkPreviewCard(data);
}

export function buildLinkPreviewCard(data: LinkPreviewData): HTMLElement {
  const card = document.createElement("a");
  card.className = "link-preview-card";
  card.href = data.finalUrl;
  card.target = "_blank";
  card.rel = "noopener noreferrer";

  if (data.image) {
    const img = document.createElement("img");
    img.className = "link-preview-image";
    img.src = data.image;
    img.alt = "";
    img.loading = "lazy";
    // A broken/unreachable preview image shouldn't leave a broken-image
    // icon sitting in the card — just drop the image slot.
    img.addEventListener("error", () => img.remove());
    card.append(img);
  }

  const body = document.createElement("div");
  body.className = "link-preview-body";

  let host = data.finalUrl;
  try {
    host = new URL(data.finalUrl).hostname;
  } catch {
    // Keep the fallback (full URL) if this somehow isn't a valid URL.
  }
  const siteRow = document.createElement("div");
  siteRow.className = "link-preview-site";
  siteRow.textContent = data.siteName || host;
  body.append(siteRow);

  if (data.title) {
    const titleEl = document.createElement("div");
    titleEl.className = "link-preview-title";
    titleEl.textContent = data.title;
    body.append(titleEl);
  }

  if (data.description) {
    const descEl = document.createElement("div");
    descEl.className = "link-preview-description";
    descEl.textContent = data.description;
    body.append(descEl);
  }

  card.append(body);
  return card;
}
