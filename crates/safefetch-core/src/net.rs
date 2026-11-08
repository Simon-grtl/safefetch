//! HTTP client construction and redirect / SSRF policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

use crate::error::{Error, Result};

pub const USER_AGENT: &str = concat!("SafeFetch/", env!("CARGO_PKG_VERSION"));

/// True if the address is globally routable (not loopback, private, link-local…).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || o[0] == 0                                   // "this network"
        || (o[0] == 100 && (o[1] & 0xC0) == 64)        // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xFE) == 18)        // 198.18/15 benchmarking
        || o[0] >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return is_public_v4(v4);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00    // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80    // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0    // site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[0..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible (deprecated)
}

/// Whether the host of a URL designates a local / private target.
pub fn host_is_local(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => !is_public_v4(ip),
        Some(Host::Ipv6(ip)) => !is_public_v6(ip),
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost"
                || d.ends_with(".localhost")
                || d.ends_with(".local")
                || !d.contains('.')
        }
        None => true,
    }
}

/// DNS resolver that refuses names resolving only to non-public addresses.
/// Used when the user typed a public URL, so a redirect (or a DNS rebinding
/// trick) cannot point the download at the LAN or at localhost.
#[derive(Debug, Default)]
pub struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                let e: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "host resolves only to private or local addresses",
                ));
                return Err(e);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub public_only: bool,
}

/// Install the process-wide rustls crypto provider (ring). Idempotent.
pub fn ensure_crypto_provider() {
    // Err only means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a client with: no automatic redirects (we follow them manually),
/// no transparent decompression, rustls with OS roots, strict timeouts.
pub fn build_client(opts: &ClientOptions) -> Result<reqwest::Client> {
    ensure_crypto_provider();
    let mut b = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(opts.connect_timeout)
        .read_timeout(opts.idle_timeout)
        .https_only(false)
        .referer(false);
    if opts.public_only {
        b = b.dns_resolver(Arc::new(PublicOnlyResolver));
    }
    b.build().map_err(crate::error::net_err)
}

/// Validate one redirect hop. `public_only` is true when the original link
/// pointed to a public host.
pub fn check_redirect(from: &Url, to: &Url, public_only: bool) -> Result<()> {
    match to.scheme() {
        "http" | "https" => {}
        s => {
            return Err(Error::Policy(format!(
                "redirect to unsupported scheme \"{s}\""
            )))
        }
    }
    if from.scheme() == "https" && to.scheme() == "http" {
        return Err(Error::Policy(
            "redirect from HTTPS to plain HTTP (downgrade) refused".into(),
        ));
    }
    if public_only && host_is_local(to) {
        return Err(Error::Policy(format!(
            "redirect from a public site to a local/private address ({}) refused",
            to.host_str().unwrap_or("?")
        )));
    }
    if !to.username().is_empty() || to.password().is_some() {
        return Err(Error::Policy("redirect URL contains credentials".into()));
    }
    Ok(())
}

/// For a redirect target when the user typed a public link: the host must
/// resolve locally, and only to public addresses. This also covers the case
/// where a system HTTP proxy is used (the proxy, not our resolver, would
/// otherwise resolve intranet names such as `intranet.corp` — audit F3).
/// Residual risk: a proxy may resolve the name differently (split DNS).
pub async fn ensure_public_target(url: &Url) -> Result<()> {
    let refuse = |h: &str| {
        Err(Error::Policy(format!(
            "redirect to a private or internal host ({h}) refused"
        )))
    };
    let host = match url.host() {
        Some(Host::Domain(d)) => d.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(ip)) => {
            return if is_public_v4(ip) {
                Ok(())
            } else {
                refuse(&ip.to_string())
            }
        }
        Some(Host::Ipv6(ip)) => {
            return if is_public_v6(ip) {
                Ok(())
            } else {
                refuse(&ip.to_string())
            }
        }
        None => return Err(Error::Policy("redirect without host".into())),
    };
    // Names that are internal by convention, whatever DNS says.
    const INTERNAL_SUFFIXES: &[&str] = &[
        ".internal",
        ".local",
        ".localhost",
        ".lan",
        ".home",
        ".corp",
        ".intranet",
        ".private",
        ".home.arpa",
    ];
    if !host.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return refuse(&host);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map(|a| a.collect::<Vec<SocketAddr>>());
    match resolved {
        Ok(addrs) if addrs.iter().any(|a| !is_public_ip(a.ip())) => refuse(&host),
        // Unresolvable locally: typical of networks where only the proxy
        // resolves names (re-audit regression). Allowed; the proxy decides.
        _ => Ok(()),
    }
}

/// A URL safe to show in the UI or logs: scheme, host and path only.
pub fn display_url(url: &Url) -> String {
    let mut s = format!("{}://{}", url.scheme(), url.host_str().unwrap_or("?"));
    if let Some(p) = url.port() {
        s.push_str(&format!(":{p}"));
    }
    let path = url.path();
    if path.len() > 80 {
        let mut cut = 77;
        while !path.is_char_boundary(cut) {
            cut -= 1;
        }
        s.push_str(&path[..cut]);
        s.push('…');
    } else {
        s.push_str(path);
    }
    if url.query().is_some() {
        s.push_str("?…");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn ip_classification() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.1.1",
            "198.18.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
        ] {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} should be non-public"
            );
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn local_hosts() {
        assert!(host_is_local(&u("http://localhost:8080/")));
        assert!(host_is_local(&u("http://foo.localhost/")));
        assert!(host_is_local(&u("http://nas/")));
        assert!(host_is_local(&u("http://printer.local/")));
        assert!(host_is_local(&u("http://[::1]/")));
        assert!(host_is_local(&u("http://0x7f000001/"))); // parsed as 127.0.0.1 by WHATWG
        assert!(!host_is_local(&u("https://example.com/")));
    }

    #[test]
    fn redirect_policy() {
        let https = u("https://example.com/a");
        let http = u("http://example.com/a");
        assert!(check_redirect(&https, &u("https://cdn.example.net/b"), true).is_ok());
        assert!(check_redirect(&http, &u("https://example.com/b"), true).is_ok());
        assert!(check_redirect(&https, &u("http://example.com/b"), true).is_err());
        assert!(check_redirect(&https, &u("https://127.0.0.1/b"), true).is_err());
        assert!(check_redirect(&https, &u("https://169.254.169.254/latest"), true).is_err());
        assert!(check_redirect(&https, &u("https://localhost/b"), true).is_err());
        assert!(check_redirect(&https, &u("file:///etc/passwd"), true).is_err());
        assert!(check_redirect(&https, &u("https://user:pw@example.com/"), true).is_err());
        // A user who typed a LAN address may be redirected within the LAN.
        assert!(
            check_redirect(&u("http://192.168.1.2/"), &u("http://192.168.1.3/"), false).is_ok()
        );
    }

    #[test]
    fn display_url_hides_query_and_userinfo() {
        let s = display_url(&u("https://user:pass@example.com/file.zip?token=SECRET"));
        assert_eq!(s, "https://example.com/file.zip?…");
        assert!(!s.contains("SECRET") && !s.contains("pass"));
    }

    #[tokio::test]
    async fn public_only_resolver_refuses_localhost() {
        let r = PublicOnlyResolver;
        let res = r.resolve("localhost".parse().unwrap()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn redirect_targets_must_resolve_publicly() {
        // Audit F3: even through a proxy, internal names are refused.
        assert!(ensure_public_target(&u("http://localhost/")).await.is_err());
        assert!(ensure_public_target(&u("http://10.0.0.1/")).await.is_err());
        assert!(ensure_public_target(&u("http://metadata.google.internal/"))
            .await
            .is_err());
        assert!(ensure_public_target(&u("http://intranet.corp/"))
            .await
            .is_err());
        assert!(ensure_public_target(&u("http://nas/")).await.is_err());
        // Proxy-only DNS: an unresolvable public-looking name is not refused.
        assert!(ensure_public_target(&u("http://cdn.example.invalid/"))
            .await
            .is_ok());
        assert!(ensure_public_target(&u("http://8.8.8.8/")).await.is_ok());
    }
}
