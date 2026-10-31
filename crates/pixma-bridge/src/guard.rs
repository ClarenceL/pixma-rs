use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Request-filtering policy for the eSCL server.
#[derive(Clone, Copy)]
pub struct GuardConfig {
    /// Accept connections from other hosts on the LAN, not just this Mac.
    /// Off by default; enabled with `PIXMA_BRIDGE_ALLOW_LAN=1`.
    pub allow_lan: bool,
}

impl GuardConfig {
    pub fn from_env() -> Self {
        Self {
            allow_lan: std::env::var("PIXMA_BRIDGE_ALLOW_LAN").is_ok_and(|v| v == "1"),
        }
    }
}

/// Reject requests that don't look like a local eSCL client (Image Capture,
/// Preview). This blocks:
/// - other hosts on the network (unless `allow_lan`), which could otherwise
///   start scans and grab the resulting images;
/// - DNS-rebinding attacks, where a web page reaches this server under an
///   attacker-controlled hostname;
/// - cross-site requests from browsers, which could start scans.
pub async fn filter(
    State(config): State<GuardConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let peer_ip = peer.ip().to_canonical();
    if !config.allow_lan && !is_local_address(peer_ip) {
        eprintln!("[guard] rejected non-local peer {peer_ip}");
        return StatusCode::FORBIDDEN.into_response();
    }

    let headers = req.headers();
    if !host_allowed(headers) {
        eprintln!(
            "[guard] rejected Host {:?} from {peer_ip}",
            headers.get(header::HOST)
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // Native eSCL clients don't send these; browsers always do on cross-origin
    // requests.
    if headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site") {
        eprintln!("[guard] rejected browser-originated request from {peer_ip}");
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(req).await
}

/// True if `ip` is loopback or one of this machine's own interface addresses
/// (Image Capture connects to the address Bonjour resolves for our hostname,
/// which is usually the LAN IP rather than 127.0.0.1).
fn is_local_address(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => ifaces.iter().any(|iface| iface.ip() == ip),
        Err(e) => {
            eprintln!("[guard] could not list interfaces: {e}");
            false
        }
    }
}

/// Accept only Host values a rebinding attacker can't control: IP literals,
/// `localhost`, and mDNS `.local` names.
fn host_allowed(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let name = match host.strip_prefix('[') {
        // IPv6 literal, e.g. "[::1]:8470"
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();

    name.parse::<IpAddr>().is_ok() || name == "localhost" || name.ends_with(".local")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with_host(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        headers
    }

    #[test]
    fn allows_local_hosts() {
        for host in [
            "localhost:8470",
            "127.0.0.1:8470",
            "192.168.0.179:8470",
            "[::1]:8470",
            "Clarences-MacBook.local:8470",
            "Clarences-MacBook.local.:8470",
            "localhost",
        ] {
            assert!(host_allowed(&with_host(host)), "{host}");
        }
    }

    #[test]
    fn rejects_rebinding_hosts() {
        for host in ["evil.example.com:8470", "localhost.evil.com", "local:8470", ""] {
            assert!(!host_allowed(&with_host(host)), "{host}");
        }
    }

    #[test]
    fn rejects_missing_host() {
        assert!(!host_allowed(&HeaderMap::new()));
    }

    #[test]
    fn loopback_is_local() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        assert!(!is_local_address("203.0.113.7".parse().unwrap()));
    }
}
