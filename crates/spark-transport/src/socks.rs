//! SOCKS5 (RFC 1928), enough of it to reach Tor and nothing more.
//!
//! Two details here are the difference between routing over Tor and appearing to.

use std::io::{Read, Write};

/// Maximum length of a hostname SOCKS5 can carry.
pub const MAX_HOST: usize = 255;

/// Open a tunnel to `host:port` through an already-connected SOCKS5 proxy.
///
/// **The hostname is sent as a name, never as an address.** RFC 1928's `ATYP=0x03`
/// exists so the proxy resolves it. Resolving locally and sending an IP would hand
/// every lookup to the local resolver — the ISP sees exactly who is being
/// contacted, and the traffic that followed was over Tor for nothing. This is the
/// most common way a Tor integration leaks, and it leaks silently.
///
/// **`isolation` becomes SOCKS5 username/password credentials.** Tor's
/// `IsolateSOCKSAuth`, which is on by default, gives a separate circuit per
/// distinct credential pair. Without it every request shares one circuit, and an
/// exit-side observer can link them to each other even though it cannot link them
/// to an IP. The password is unused and fixed; only the username varies.
pub fn connect<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    isolation: &str,
) -> Result<(), SocksError> {
    if host.is_empty() || host.len() > MAX_HOST {
        return Err(SocksError::BadHost);
    }

    // Greeting: offer username/password only. Offering "no auth" as well would let
    // a proxy choose it and silently drop stream isolation.
    stream
        .write_all(&[0x05, 0x01, 0x02])
        .map_err(|_| SocksError::Io)?;
    let mut r = [0u8; 2];
    stream.read_exact(&mut r).map_err(|_| SocksError::Io)?;
    if r[0] != 0x05 {
        return Err(SocksError::NotSocks5);
    }
    if r[1] != 0x02 {
        return Err(SocksError::NoIsolation);
    }

    // RFC 1929 username/password. The username is the isolation token.
    let user = isolation.as_bytes();
    if user.is_empty() || user.len() > 255 {
        return Err(SocksError::BadIsolation);
    }
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user);
    auth.extend_from_slice(&[0x01, b'-']); // password: one fixed byte, unused
    stream.write_all(&auth).map_err(|_| SocksError::Io)?;
    let mut a = [0u8; 2];
    stream.read_exact(&mut a).map_err(|_| SocksError::Io)?;
    if a[1] != 0x00 {
        return Err(SocksError::AuthRejected);
    }

    // CONNECT, by domain name.
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).map_err(|_| SocksError::Io)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(|_| SocksError::Io)?;
    if head[0] != 0x05 {
        return Err(SocksError::NotSocks5);
    }
    if head[1] != 0x00 {
        return Err(SocksError::Refused(head[1]));
    }
    // Drain the bound address, whose length depends on its type.
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).map_err(|_| SocksError::Io)?;
            l[0] as usize + 2
        }
        _ => return Err(SocksError::NotSocks5),
    };
    let mut drain = vec![0u8; rest];
    stream.read_exact(&mut drain).map_err(|_| SocksError::Io)?;
    Ok(())
}

/// Why a SOCKS5 tunnel could not be opened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SocksError {
    /// The transport failed underneath.
    Io,
    /// The peer is not speaking SOCKS5.
    NotSocks5,
    /// The proxy refused username/password, so stream isolation is unavailable.
    ///
    /// Treated as fatal rather than falling back to no-auth. A fallback would
    /// mean every request sharing one circuit while the user was told otherwise.
    NoIsolation,
    /// The proxy rejected the isolation credentials.
    AuthRejected,
    /// The hostname is empty or longer than SOCKS5 can carry.
    BadHost,
    /// The isolation token is empty or too long.
    BadIsolation,
    /// The proxy refused the CONNECT, with RFC 1928's reply code.
    Refused(u8),
}

impl core::fmt::Display for SocksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => f.write_str("proxy connection failed"),
            Self::NotSocks5 => f.write_str("proxy is not speaking SOCKS5"),
            Self::NoIsolation => f.write_str("proxy will not do per-circuit isolation"),
            Self::AuthRejected => f.write_str("proxy rejected the isolation credentials"),
            Self::BadHost => f.write_str("hostname is empty or too long for SOCKS5"),
            Self::BadIsolation => f.write_str("isolation token is empty or too long"),
            Self::Refused(c) => write!(f, "proxy refused the connection (code {c})"),
        }
    }
}
impl core::error::Error for SocksError {}
