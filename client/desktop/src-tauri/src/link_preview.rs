//! Client-side, opt-in Open Graph link preview fetcher.
//!
//! This talks directly to whatever host the pasted URL points at. It must
//! NEVER go through the daemon (`daemon_health`/`panic_wipe_daemon` in
//! `lib.rs`) or any operator-visible relay — the daemon has no idea this
//! request exists — and the frontend must only invoke it when the user has
//! explicitly turned link previews on *and* pressed this specific link's
//! "Load preview" button (see `src/link_preview.ts`'s
//! `renderLinkPreviewSlot`): fetching an arbitrary link necessarily
//! reveals the user's IP address, and the timing of the fetch, to whatever
//! site is linked. Rendering a message must therefore never trigger one on
//! its own — that handed the sender a covert read receipt for the moment a
//! conversation was opened. That's a real privacy tradeoff, not something
//! to hide behind a quiet default-on setting — see the opt-in copy in
//! `src/link_preview.ts`.
//!
//! Both network round trips this module makes ([`fetch`] for the page's
//! HTML, [`fetch_image`] for its `og:image`) go through the same host
//! validation and the same public-addresses-only DNS resolver. The image
//! one exists precisely so the webview never issues that second request
//! itself against a URL the untrusted page chose.

use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use ureq::{Error as UreqError, ResponseExt};

/// Generous enough for a page's `<head>` (where OG tags live) while
/// capping memory use and making this an unattractive vector for someone
/// to point the user at a multi-gigabyte response.
const MAX_PREVIEW_BYTES: u64 = 2 * 1024 * 1024;
/// Same spirit as [`MAX_PREVIEW_BYTES`], sized for a card thumbnail rather
/// than a document. Bounded here because the bytes get base64-encoded into
/// a `data:` URL for the webview, which costs another ~33% on top.
const MAX_PREVIEW_IMAGE_BYTES: u64 = 3 * 1024 * 1024;
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REDIRECTS: u32 = 5;
/// Generic, non-identifying UA — this is a metadata fetch on the user's
/// behalf, not a real browsing session, and shouldn't fingerprint the app
/// or device beyond "some Open Graph scraper".
const PREVIEW_USER_AGENT: &str = "Mozilla/5.0 (compatible; BlackholeLinkPreview/1.0)";

/// A preview image, already fetched and inlined — the frontend turns this
/// into a `data:` URL rather than pointing an `<img src>` at the remote
/// host itself. See [`fetch_image`] for why that indirection exists.
#[derive(Serialize)]
pub struct LinkPreviewImageResponse {
    pub content_type: String,
    pub bytes_base64: String,
}

#[derive(Serialize)]
pub struct LinkPreviewResponse {
    /// The URL actually fetched after following redirects — the frontend
    /// resolves relative `og:image` URLs against this, not the original.
    pub final_url: String,
    pub content_type: String,
    pub html: String,
}

/// Best-effort SSRF guard: refuses literal loopback/private/link-local
/// addresses and `localhost`.
///
/// This is a fast-path check on the URL string only — it does NOT resolve
/// the hostname itself, so a public domain name that happens to resolve to
/// an internal address (DNS rebinding) would sail through *this specific
/// function*. That gap is closed at the actual connection layer instead:
/// [`PinningResolver`] filters `fetch`'s real DNS resolution down to
/// public addresses only, for the initial request and every redirect hop,
/// so the address that's actually connected to is always the one that was
/// validated — not just whatever this string-level check happened to see.
fn is_blocked_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => is_non_public_ip(IpAddr::V4(*ip)),
        url::Host::Ipv6(ip) => is_non_public_ip(IpAddr::V6(*ip)),
        url::Host::Domain(domain) => {
            let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            domain.is_empty() || domain == "localhost" || domain.ends_with(".localhost")
        }
    }
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_public_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d)
            // address connects to the embedded IPv4 host, so it has to be
            // judged as that IPv4 address — otherwise `::ffff:127.0.0.1`
            // sails through as "some IPv6 address that isn't loopback".
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_non_public_v4(mapped);
            }
            let segments = v6.segments();
            if segments[..6] == [0, 0, 0, 0, 0, 0] && !v6.is_loopback() && !v6.is_unspecified() {
                // IPv4-compatible ::a.b.c.d (deprecated, but still routable
                // as the embedded IPv4 address by some stacks).
                let embedded =
                    std::net::Ipv4Addr::from(((segments[6] as u32) << 16) | segments[7] as u32);
                return is_non_public_v4(embedded);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            // `Ipv6Addr::is_unique_local`/`is_unicast_link_local` are still
            // unstable on stable Rust, hence the manual range checks for
            // fc00::/7 (unique local) and fe80::/10 (link-local).
            let seg0 = segments[0];
            (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Everything that isn't globally routable unicast. `Ipv4Addr::is_global`
/// is still unstable on stable Rust, so the non-obvious ranges are spelled
/// out here rather than approximated by
/// `is_private() || is_loopback() || is_link_local()` alone — a preview
/// fetch that lands on carrier-grade NAT space or `0.0.0.0/8` is reaching
/// something on the user's own side of the internet just as surely as one
/// that lands on `10.0.0.0/8`.
fn is_non_public_v4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // "This network" — 0.0.0.0/8, of which `is_unspecified` only covers
        // the single address 0.0.0.0.
        || a == 0
        // Carrier-grade NAT, 100.64.0.0/10.
        || (a == 100 && (64..128).contains(&b))
        // IETF protocol assignments, 192.0.0.0/24.
        || (v4.octets()[..3] == [192, 0, 0])
        // Benchmarking, 198.18.0.0/15.
        || (a == 198 && (b == 18 || b == 19))
        // Reserved, 240.0.0.0/4 (`is_broadcast` only covers 255.255.255.255).
        || a >= 240
}

/// Resolves the same way [`DefaultResolver`] does, then rejects the
/// lookup outright if every resolved address is loopback/private/
/// link-local — closing the DNS-rebinding gap [`is_blocked_host`]'s doc
/// comment flags: a public domain name that resolves to an internal
/// address wasn't caught by the string-level host check above, because
/// that check runs before DNS resolution and `ureq`'s own connector
/// re-resolves independently. Wiring this in as the actual resolver means
/// the address that gets *connected to* is the one that was validated,
/// for the initial request and every redirect hop (`max_redirects`
/// reuses the same `Agent`/resolver).
#[derive(Debug, Default)]
struct PinningResolver {
    inner: DefaultResolver,
}

impl Resolver for PinningResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, UreqError> {
        let resolved = self.inner.resolve(uri, config, timeout)?;
        keep_only_public_addrs(resolved)
    }
}

/// Filters a resolver's output down to public addresses only, erroring if
/// none remain. Split out from [`PinningResolver::resolve`] so this
/// filtering logic — the actual DNS-rebinding fix — is unit-testable
/// against synthetic resolver output, without needing a real DNS lookup.
fn keep_only_public_addrs(resolved: ResolvedSocketAddrs) -> Result<ResolvedSocketAddrs, UreqError> {
    let mut public_only = ResolvedSocketAddrs::from_fn(|_| {
        std::net::SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    });
    for addr in resolved.iter().filter(|addr| !is_non_public_ip(addr.ip())) {
        public_only.push(*addr);
    }
    if public_only.is_empty() {
        return Err(UreqError::HostNotFound);
    }
    Ok(public_only)
}

fn validate_preview_url(raw: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(raw.trim()).map_err(|_| "not a valid URL".to_string())?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("only http/https links can have previews".to_string());
    }
    let host = parsed.host().ok_or_else(|| "URL has no host".to_string())?;
    if is_blocked_host(&host) {
        return Err("refusing to fetch a local/private address".to_string());
    }
    Ok(parsed)
}

/// An agent whose DNS resolution is pinned to public addresses only — see
/// [`PinningResolver`]. `Agent::with_parts` rather than `config.into()`
/// specifically so that resolver is the one actually used at connect time.
fn guarded_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(PREVIEW_TIMEOUT))
        .max_redirects(MAX_REDIRECTS)
        .build();
    ureq::Agent::with_parts(
        config,
        DefaultConnector::default(),
        PinningResolver::default(),
    )
}

/// Fetches a preview image (an `og:image` URL the *linked page* chose) and
/// returns its bytes for the frontend to inline as a `data:` URL.
///
/// This exists because an `og:image` is attacker-controlled content from
/// the same untrusted page whose HTML [`fetch`] just retrieved. Letting the
/// webview point an `<img src>` at it directly would issue a request that
/// never passes through [`validate_preview_url`] or [`PinningResolver`] at
/// all — the webview's own network stack does its own DNS and its own
/// connection — so a page could aim the user's client at `127.0.0.1`, a LAN
/// host, or an unrelated third-party tracker, none of which the guards on
/// the HTML fetch would ever see. Routing the image through the same
/// guarded agent keeps one enforcement point for "what this feature is
/// allowed to connect to".
pub fn fetch_image(raw_url: &str) -> Result<LinkPreviewImageResponse, String> {
    use base64::Engine as _;

    let parsed = validate_preview_url(raw_url)?;
    let mut response = guarded_agent()
        .get(parsed.as_str())
        .header("User-Agent", PREVIEW_USER_AGENT)
        .header("Accept", "image/*")
        .call()
        .map_err(|e| format!("fetch failed: {e}"))?;

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    // Refuse to hand the webview something that isn't an image: a `data:`
    // URL is same-origin for CSP purposes, so an HTML/SVG-with-script body
    // inlined under an `<img>` is not a shape worth allowing at all.
    if !content_type.starts_with("image/") || content_type == "image/svg+xml" {
        return Err(format!("not a renderable image ({content_type})"));
    }

    let mut bytes = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit(MAX_PREVIEW_IMAGE_BYTES)
        .reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed reading image body: {e}"))?;

    Ok(LinkPreviewImageResponse {
        content_type,
        bytes_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    })
}

/// Fetches a URL and returns raw HTML for the frontend to scan for
/// `<meta property="og:*">` tags (parsing happens in
/// `src/link_preview.ts`, not here — this command's only job is the
/// network round trip and the safety checks around it).
pub fn fetch(raw_url: &str) -> Result<LinkPreviewResponse, String> {
    let parsed = validate_preview_url(raw_url)?;

    let mut response = guarded_agent()
        .get(parsed.as_str())
        .header("User-Agent", PREVIEW_USER_AGENT)
        .header("Accept", "text/html,application/xhtml+xml")
        .call()
        .map_err(|e| format!("fetch failed: {e}"))?;

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let final_url = response.get_uri().to_string();

    let html = response
        .body_mut()
        .with_config()
        .limit(MAX_PREVIEW_BYTES)
        .read_to_string()
        .map_err(|e| format!("failed reading response body: {e}"))?;

    Ok(LinkPreviewResponse {
        final_url,
        content_type,
        html,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct unit test of the DNS-rebinding fix: even though
    /// `is_blocked_host`'s string-level check never sees a resolved IP,
    /// `keep_only_public_addrs` (the filter `PinningResolver::resolve`
    /// applies to whatever the real DNS lookup returns) must reject a
    /// lookup whose resolved addresses are all private — this is the
    /// actual guard exercised at connect time, string validation is only
    /// the fast-path front door.
    #[test]
    fn rejects_a_lookup_that_resolves_only_to_private_addresses() {
        use std::net::{Ipv4Addr, SocketAddr};

        let mut all_private =
            ResolvedSocketAddrs::from_fn(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        all_private.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80));
        all_private.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 80));

        assert!(keep_only_public_addrs(all_private).is_err());
    }

    #[test]
    fn keeps_public_addresses_and_drops_private_ones_from_a_mixed_result() {
        use std::net::{Ipv4Addr, SocketAddr};

        let mut mixed =
            ResolvedSocketAddrs::from_fn(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        mixed.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80));
        mixed.push(public_addr);

        let filtered = keep_only_public_addrs(mixed).unwrap();
        assert_eq!(&*filtered, &[public_addr]);
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_preview_url("file:///etc/passwd").is_err());
        assert!(validate_preview_url("javascript:alert(1)").is_err());
        assert!(validate_preview_url("data:text/html,hi").is_err());
    }

    #[test]
    fn rejects_loopback_and_private_hosts() {
        assert!(validate_preview_url("http://localhost/x").is_err());
        assert!(validate_preview_url("http://LOCALHOST/x").is_err());
        assert!(validate_preview_url("http://127.0.0.1/x").is_err());
        assert!(validate_preview_url("http://[::1]/x").is_err());
        // Cloud metadata endpoint — the classic SSRF target.
        assert!(validate_preview_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_preview_url("http://10.0.0.5/x").is_err());
        assert!(validate_preview_url("http://172.16.0.5/x").is_err());
        assert!(validate_preview_url("http://192.168.1.1/x").is_err());
        assert!(validate_preview_url("http://[fe80::1]/x").is_err());
        assert!(validate_preview_url("http://[fc00::1]/x").is_err());
    }

    /// An IPv4-mapped IPv6 address connects to the embedded IPv4 host, so
    /// `::ffff:127.0.0.1` is loopback no matter which family it's written
    /// in. Before this it was judged purely as an IPv6 address — not
    /// loopback, not ULA, not link-local — and was allowed through.
    #[test]
    fn rejects_ipv4_mapped_and_compatible_ipv6_loopback_and_private_addresses() {
        assert!(validate_preview_url("http://[::ffff:127.0.0.1]/x").is_err());
        assert!(validate_preview_url("http://[::ffff:10.0.0.5]/x").is_err());
        assert!(validate_preview_url("http://[::ffff:169.254.169.254]/x").is_err());
        assert!(validate_preview_url("http://[::127.0.0.1]/x").is_err());
        // The same encoding of a genuinely public address must still pass.
        assert!(validate_preview_url("http://[::ffff:93.184.216.34]/x").is_ok());
    }

    /// Ranges `is_private`/`is_loopback`/`is_link_local` don't cover but
    /// which still aren't the public internet.
    #[test]
    fn rejects_cgnat_this_network_and_other_reserved_v4_ranges() {
        // Carrier-grade NAT (100.64.0.0/10) — the user's ISP-side network.
        assert!(validate_preview_url("http://100.64.0.1/x").is_err());
        assert!(validate_preview_url("http://100.127.255.254/x").is_err());
        // 0.0.0.0/8, of which only 0.0.0.0 itself was caught before.
        assert!(validate_preview_url("http://0.1.2.3/x").is_err());
        // IETF protocol assignments, benchmarking, and reserved space.
        assert!(validate_preview_url("http://192.0.0.1/x").is_err());
        assert!(validate_preview_url("http://198.18.0.1/x").is_err());
        assert!(validate_preview_url("http://240.0.0.1/x").is_err());
        // Adjacent-but-public addresses must NOT be swept up by the above.
        assert!(validate_preview_url("http://100.63.255.255/x").is_ok());
        assert!(validate_preview_url("http://100.128.0.1/x").is_ok());
        assert!(validate_preview_url("http://198.20.0.1/x").is_ok());
        assert!(validate_preview_url("http://192.0.1.1/x").is_ok());
    }

    #[test]
    fn accepts_a_well_formed_public_url() {
        assert!(validate_preview_url("https://example.com/page?x=1").is_ok());
        assert!(validate_preview_url("  https://example.com/page  ").is_ok());
    }

    #[test]
    fn rejects_garbage_input() {
        assert!(validate_preview_url("not a url").is_err());
        assert!(validate_preview_url("").is_err());
    }
}
