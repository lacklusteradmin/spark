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
use spark_transport::hysteria::{Frame as CoverFrame, Hysteria, Reassembler};
use spark_transport::{Channel, ChannelError, Class};
use spark_wire::{Frame, content, issuer, keyring};
use std::net::TcpListener;
use std::sync::Arc;

use spark_content_server::Content;
use spark_issuer::Issuer;
use spark_keyring_server::Keyring;

// One absolute deadline for a complete handshake or application frame. A
// socket timeout alone restarts on each byte and permits indefinite slow drips.
#[derive(Clone)]
struct Deadline(Arc<std::sync::Mutex<std::time::Instant>>);
impl Deadline {
    fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(
            std::time::Instant::now() + std::time::Duration::from_secs(15),
        )))
    }
    fn restart(&self) {
        *self.0.lock().unwrap() = std::time::Instant::now() + std::time::Duration::from_secs(90);
    }
    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        self.0
            .lock()
            .unwrap()
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline"))
    }
}
struct DeadlineSocket {
    stream: std::net::TcpStream,
    deadline: Deadline,
}
impl std::io::Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        std::io::Read::read(&mut self.stream, bytes)
    }
}
impl std::io::Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        std::io::Write::write(&mut self.stream, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

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
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            use std::sync::atomic::Ordering;
            if active
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < 128).then_some(n + 1)
                })
                .is_err()
            {
                continue;
            }
            struct Permit(Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Permit {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let permit = Permit(active.clone());
            let timeout = Some(std::time::Duration::from_secs(15));
            if stream.set_read_timeout(timeout).is_err()
                || stream.set_write_timeout(timeout).is_err()
            {
                continue;
            }
            let (f, tls) = (f.clone(), tls.clone());
            // One thread per connection. A connection that misbehaves — including
            // one that fails the TLS handshake — takes down its own thread and
            // nothing else.
            std::thread::spawn(move || {
                let _permit = permit;
                let Ok(conn) = rustls::ServerConnection::new(tls) else {
                    return;
                };
                let deadline = Deadline::new();
                let stream = DeadlineSocket {
                    stream,
                    deadline: deadline.clone(),
                };
                let _ = session(rustls::StreamOwned::new(conn, stream), f.as_ref(), deadline);
            });
        }
    });
    Ok(Listener { addr, handle })
}

fn session<S, Q, R, F>(stream: S, f: &F, deadline: Deadline) -> Result<(), ChannelError>
where
    S: std::io::Read + std::io::Write,
    Q: serde::de::DeserializeOwned + spark_wire::Operation,
    R: serde::Serialize + spark_wire::Operation,
    F: Fn(Q) -> R,
{
    let mut ch = Channel::accept(stream)?;

    // Which mode this connection is in is decided by its first message: a cover
    // frame is exactly FRAME_BYTES long and a protocol frame almost never is.
    // Deciding per connection rather than per message means a peer cannot switch
    // halfway and get a variable-length answer out of a paced session.
    deadline.restart();
    let first = match ch.recv_raw() {
        Ok(b) => b,
        Err(ChannelError::Closed) => return Ok(()),
        Err(e) => return Err(e),
    };
    match CoverFrame::from_bytes(&first) {
        Some(cover) => paced_session(ch, cover, f, deadline),
        None => plain_session(ch, Frame::from_bytes(&first)?, f, deadline),
    }
}

/// A session where each side transmits one uniform frame at a time.
///
/// The server is not paced — it only ever answers, so its transmissions already
/// land on the client's schedule. What it must do is keep them the same *size*: a
/// 4 KB request answered by an 8 KB reply tells an observer a real request went
/// out, and the client's cadence bought nothing.
fn paced_session<S, Q, R, F>(
    mut ch: Channel<S>,
    first: CoverFrame,
    f: &F,
    deadline: Deadline,
) -> Result<(), ChannelError>
where
    S: std::io::Read + std::io::Write,
    Q: serde::de::DeserializeOwned + spark_wire::Operation,
    R: serde::Serialize + spark_wire::Operation,
    F: Fn(Q) -> R,
{
    let mut inbound = Reassembler::new();
    let mut outbound = Hysteria::new();
    let mut cover = first;
    loop {
        let msgs = inbound
            .accept(&cover)
            .map_err(|_| ChannelError::Wire(spark_wire::WireError::Malformed))?;
        for m in msgs {
            let frame = Frame::from_bytes(&m)?;
            let req: Q = frame.body()?;
            let reply = Frame::encode(frame.req_id, &f(req))?.to_bytes();
            outbound
                .enqueue(Class::Text, &reply)
                .map_err(|_| ChannelError::Wire(spark_wire::WireError::Encode))?;
        }
        // One frame back per frame received, carrying whatever is queued — a reply,
        // part of one, or nothing. Answering a dummy with silence would make dummies
        // recognisable, which is the whole thing being defended against.
        deadline.restart();
        ch.send_raw(outbound.tick().as_bytes())?;

        deadline.restart();
        cover = match ch.recv_raw() {
            Ok(b) => CoverFrame::from_bytes(&b)
                .ok_or(ChannelError::Wire(spark_wire::WireError::Malformed))?,
            Err(ChannelError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
    }
}

/// A session without cover traffic: one protocol frame in, one out.
fn plain_session<S, Q, R, F>(
    mut ch: Channel<S>,
    first: Frame,
    f: &F,
    deadline: Deadline,
) -> Result<(), ChannelError>
where
    S: std::io::Read + std::io::Write,
    Q: serde::de::DeserializeOwned + spark_wire::Operation,
    R: serde::Serialize + spark_wire::Operation,
    F: Fn(Q) -> R,
{
    let mut frame = first;
    loop {
        // A frame that does not decode ends the session. Answering it would mean
        // telling a peer which malformed inputs get further than others.
        let req: Q = frame.body()?;
        let response = f(req);
        deadline.restart();
        ch.reply(frame.req_id, &response)?;
        deadline.restart();
        frame = match ch.recv() {
            Ok(f) => f,
            // A closed connection is how a session ends, not an error to report.
            Err(ChannelError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
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

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn partial_reads_cannot_extend_the_absolute_deadline() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut writer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let deadline = Deadline::new();
        *deadline.0.lock().unwrap() =
            std::time::Instant::now() + std::time::Duration::from_millis(50);
        let mut socket = DeadlineSocket { stream, deadline };
        let drip = std::thread::spawn(move || {
            for _ in 0..20 {
                if writer.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        let mut got = 0;
        while socket.read_exact(&mut [0]).is_ok() {
            got += 1;
        }
        assert!(got < 20, "every small read reset the deadline");
        drop(socket);
        drip.join().unwrap();
    }
    #[test]
    fn frame_budget_allows_the_default_minute_cover_interval() {
        let deadline = Deadline::new();
        deadline.restart();
        assert!(deadline.remaining().unwrap() > std::time::Duration::from_secs(60));
    }
}
