//! Client-side, opt-in Open Graph link preview fetcher.
//!
//! This talks directly to whatever host the pasted URL points at. It must
//! NEVER go through the daemon (`daemon_health`/`panic_wipe_daemon` in
//! `lib.rs`) or any operator-visible relay — the daemon has no idea this
//! request exists — and the frontend must only invoke it when the user has
//! explicitly turned link previews on (see `src/link_preview.ts`):
//! fetching an arbitrary link necessarily reveals the user's IP address
//! (and that they opened this conversation) to whatever site is linked.
//! That's a real privacy tradeoff, not something to hide behind a quiet
//! default-on setting — see the opt-in copy in `src/link_preview.ts`.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use ureq::ResponseExt;

/// Generous enough for a page's `<head>` (where OG tags live) while
/// capping memory use and making this an unattractive vector for someone
/// to point the user at a multi-gigabyte response.
const MAX_PREVIEW_BYTES: u64 = 2 * 1024 * 1024;
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REDIRECTS: u32 = 5;
/// Generic, non-identifying UA — this is a metadata fetch on the user's
/// behalf, not a real browsing session, and shouldn't fingerprint the app
/// or device beyond "some Open Graph scraper".
const PREVIEW_USER_AGENT: &str = "Mozilla/5.0 (compatible; BlackholeLinkPreview/1.0)";

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
/// This does NOT resolve the hostname itself, so a public domain name that
/// happens to resolve to an internal address (DNS rebinding) is not caught
/// here. That's an accepted gap for a feature the *user* triggers by
/// pasting a link they chose to paste — it is not attacker-reachable
/// without the user's own participation — but it would need real fixing
/// (resolve-then-pin-the-IP) before this code is ever reused somewhere the
/// URL is attacker-controlled.
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
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            // `Ipv6Addr::is_unique_local`/`is_unicast_link_local` are still
            // unstable on stable Rust, hence the manual range checks for
            // fc00::/7 (unique local) and fe80::/10 (link-local).
            let seg0 = v6.segments()[0];
            (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
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

/// Fetches a URL and returns raw HTML for the frontend to scan for
/// `<meta property="og:*">` tags (parsing happens in
/// `src/link_preview.ts`, not here — this command's only job is the
/// network round trip and the safety checks around it).
pub fn fetch(raw_url: &str) -> Result<LinkPreviewResponse, String> {
    let parsed = validate_preview_url(raw_url)?;

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(PREVIEW_TIMEOUT))
        .max_redirects(MAX_REDIRECTS)
        .build();
    let agent: ureq::Agent = config.into();

    let mut response = agent
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
