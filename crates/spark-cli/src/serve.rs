//! Serving the three services over the wire.
//!
//! `docs/protocol.md` §6. One thread per connection, one connection per service:
//! the services are separate trust domains and separate listeners, so a
//! deployment that runs them on one machine is a *choice* rather than something
//! the code assumed.
//!
//! TLS wraps the stream before the WebSocket handshake. Everything Spark sends is
//! already sealed, so what TLS adds is server authentication and hiding the
//! request pattern from a passive observer — neither of which the encryption above
//! it does. The client pins the server's public key rather than consulting a
//! certificate authority; see `spark_transport::tls` for why.

use rustls::ServerConfig;
use spark_transport::{Channel, ChannelError};
use spark_wire::{Frame, content, issuer, keyring};
use std::net::TcpListener;
use std::sync::Arc;

/// A TLS-wrapped TCP connection.
type Tls = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

use spark_content_server::Content;
use spark_issuer::Issuer;
use spark_keyring_server::Keyring;

/// A listening service.
pub struct Listener {
    /// Where it is listening.
    pub addr: std::net::SocketAddr,
    handle: std::thread::JoinHandle<()>,
}

impl Listener {
    /// Wait for the listener to stop, which it does when its socket closes.
    pub fn join(self) {
        let _ = self.handle.join();
    }
}

/// Serve one service on `bind`, dispatching each request through `f`.
fn serve<Q, R, F>(bind: &str, tls: Arc<ServerConfig>, f: F) -> std::io::Result<Listener>
where
    Q: serde::de::DeserializeOwned + spark_wire::Operation + Send + 'static,
    R: serde::Serialize + spark_wire::Operation + Send + 'static,
    F: Fn(Q) -> R + Send + Sync + 'static,
{
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    let f = Arc::new(f);
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let (f, tls) = (f.clone(), tls.clone());
            // One thread per connection. A connection that misbehaves — including
            // one that fails the TLS handshake — takes down its own thread and
            // nothing else.
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(tls) else {
                    return;
                };
                let _ = session(rustls::StreamOwned::new(conn, stream), f.as_ref());
            });
        }
    });
    Ok(Listener { addr, handle })
}

fn session<Q, R, F>(stream: Tls, f: &F) -> Result<(), ChannelError>
where
    Q: serde::de::DeserializeOwned + spark_wire::Operation,
    R: serde::Serialize + spark_wire::Operation,
    F: Fn(Q) -> R,
{
    let mut ch = Channel::accept(stream)?;
    loop {
        let frame: Frame = match ch.recv() {
            Ok(f) => f,
            // A closed connection is how a session ends, not an error to report.
            Err(ChannelError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        // A frame that does not decode ends the session. Answering it would mean
        // telling a peer which malformed inputs get further than others.
        let req: Q = frame.body()?;
        ch.reply(frame.req_id, &f(req))?;
    }
}

/// Serve the keyring service.
pub fn keyring_service(
    bind: &str,
    tls: Arc<ServerConfig>,
    svc: Arc<Keyring>,
) -> std::io::Result<Listener> {
    serve(bind, tls, move |r: keyring::Req| svc.handle_wire(r))
}

/// Serve the content service.
pub fn content_service(
    bind: &str,
    tls: Arc<ServerConfig>,
    svc: Arc<Content>,
) -> std::io::Result<Listener> {
    serve(bind, tls, move |r: content::Req| svc.handle_wire(r))
}

/// Serve the issuer.
pub fn issuer_service(
    bind: &str,
    tls: Arc<ServerConfig>,
    svc: Arc<Issuer>,
) -> std::io::Result<Listener> {
    serve(bind, tls, move |r: issuer::Req| svc.handle_wire(r))
}
