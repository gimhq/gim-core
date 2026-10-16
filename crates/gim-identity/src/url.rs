//! Normalization of a hub's public client API URL: the `public_url` of
//! `GET /v2/hub`, signed by the hub proof, and the `audience_url` of an
//! [`AuthChallenge`](crate::AuthChallenge) v2.

use std::net::Ipv6Addr;

use crate::IdentityError;

/// Longest accepted input, in bytes.
pub const MAX_HUB_URL_LEN: usize = 65_535;

fn invalid(reason: &str) -> IdentityError {
    IdentityError::InvalidUrl(reason.into())
}

/// Normalizes a hub URL to `scheme://host[:port]` (`docs/identity.md`,
/// "Hub URLs"): surrounding whitespace is trimmed; the scheme is `http` or
/// `https` (any case), the host a DNS name of `[a-z0-9-]` labels, an IPv4
/// address or a bracketed IPv6 address (lowercased); the port is dropped
/// when it is the scheme's default; only an empty path or a single `/` is
/// allowed. Userinfo, other paths, a query (even an empty one), a fragment,
/// percent-encoding and non-ASCII input are rejected.
pub fn normalize_hub_url(input: &str) -> Result<String, IdentityError> {
    if input.len() > MAX_HUB_URL_LEN {
        return Err(invalid("too long"));
    }
    let input = input.trim_ascii();
    if !input.is_ascii() {
        return Err(invalid("non-ASCII"));
    }
    if input.contains('%') {
        return Err(invalid("percent-encoding"));
    }
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| invalid("no scheme"))?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(invalid("scheme is not http or https")),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if tail.contains('?') {
        return Err(invalid("query"));
    }
    if tail.contains('#') {
        return Err(invalid("fragment"));
    }
    if !tail.is_empty() && tail != "/" {
        return Err(invalid("path"));
    }
    if authority.contains('@') {
        return Err(invalid("userinfo"));
    }
    let (host, port) = split_host_port(authority)?;
    let port = match port {
        None => None,
        Some(port) => Some(parse_port(port)?).filter(|&port| port != default_port),
    };
    Ok(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

/// The lowercased host and the port text after `:`, if any.
fn split_host_port(authority: &str) -> Result<(String, Option<&str>), IdentityError> {
    if let Some(literal) = authority.strip_prefix('[') {
        let (address, after) = literal
            .split_once(']')
            .ok_or_else(|| invalid("unterminated IPv6 literal"))?;
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| invalid("invalid IPv6 literal"))?;
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("garbage after IPv6 literal"))?,
            ),
        };
        return Ok((format!("[{}]", address.to_ascii_lowercase()), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    if host.ends_with('.') {
        return Err(invalid("trailing dot"));
    }
    let host = host.to_ascii_lowercase();
    for label in host.split('.') {
        if label.is_empty() {
            return Err(invalid("empty DNS label"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid("invalid host character"));
        }
    }
    Ok((host, port))
}

/// A decimal port in `1..=65535`; leading zeros are allowed.
fn parse_port(port: &str) -> Result<u16, IdentityError> {
    if port.is_empty() {
        return Err(invalid("empty port"));
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("port is not decimal digits"));
    }
    let digits = port.trim_start_matches('0');
    match digits.parse::<u16>() {
        _ if digits.is_empty() => Err(invalid("port 0")),
        Ok(port) => Ok(port),
        Err(_) => Err(invalid("port out of range")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_long_input_and_bad_ports() {
        let long = format!("https://{}.eu", "a".repeat(MAX_HUB_URL_LEN));
        assert!(normalize_hub_url(&long).is_err());
        assert!(normalize_hub_url("https://hub.eu:000").is_err());
        assert!(normalize_hub_url("https://hub.eu:99999999999999999999").is_err());
        assert_eq!(
            normalize_hub_url("https://hub.eu:00443").unwrap(),
            "https://hub.eu"
        );
        assert!(normalize_hub_url("https://[::1]:").is_err());
        assert!(normalize_hub_url("https://[::1]/x").is_err());
    }
}
