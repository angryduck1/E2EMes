//! Request/response multiplexing over the encrypted transport.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use e2emes_proto::{transport::client_handshake, ApiError, ClientFrame, Event, Request, Response, ServerFrame};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Waiters for responses; `None` once the connection is gone.
type Pending = Arc<Mutex<Option<HashMap<u64, oneshot::Sender<Result<Response, ApiError>>>>>>;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("disconnected from the server")]
    Disconnected,
    #[error("the server did not answer in time")]
    Timeout,
}

/// A live connection. Cloning is cheap; all clones share the same socket.
#[derive(Clone)]
pub struct Connection {
    outgoing: mpsc::Sender<ClientFrame>,
    pending: Pending,
    next_id: Arc<AtomicU64>,
}

/// Connects and authenticates the server by its static public key.
/// Events pushed by the server arrive on the returned receiver; it closes when
/// the connection is lost.
pub async fn connect(
    addr: &str,
    server_public: &[u8; 32],
) -> anyhow::Result<(Connection, mpsc::UnboundedReceiver<Event>)> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("connecting to {addr} timed out"))??;
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = timeout(CONNECT_TIMEOUT, client_handshake(stream, server_public))
        .await
        .map_err(|_| anyhow::anyhow!("handshake with {addr} timed out"))?
        .map_err(|e| anyhow::anyhow!("handshake with {addr} failed (wrong server key?): {e}"))?;

    let (outgoing, mut outgoing_rx) = mpsc::channel::<ClientFrame>(64);
    tokio::spawn(async move {
        while let Some(frame) = outgoing_rx.recv().await {
            if writer.send(&frame).await.is_err() {
                break;
            }
        }
        writer.shutdown().await;
    });

    let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let reader_pending = pending.clone();
    tokio::spawn(async move {
        while let Ok(frame) = reader.recv::<ServerFrame>().await {
            match frame {
                ServerFrame::Response { id, result } => {
                    let waiter = reader_pending.lock().unwrap().as_mut().and_then(|p| p.remove(&id));
                    if let Some(waiter) = waiter {
                        let _ = waiter.send(result);
                    }
                }
                ServerFrame::Event(event) => {
                    let _ = events_tx.send(event);
                }
            }
        }
        // Wake up everyone still waiting (dropping the senders reports `Disconnected`)
        // and make later requests fail at once instead of waiting for the timeout.
        reader_pending.lock().unwrap().take();
    });

    Ok((
        Connection {
            outgoing,
            pending,
            next_id: Arc::new(AtomicU64::new(1)),
        },
        events_rx,
    ))
}

impl Connection {
    pub async fn request(&self, request: Request) -> Result<Response, RequestError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        match self.pending.lock().unwrap().as_mut() {
            Some(pending) => pending.insert(id, tx),
            None => return Err(RequestError::Disconnected),
        };
        if self.outgoing.send(ClientFrame { id, request }).await.is_err() {
            self.forget(id);
            return Err(RequestError::Disconnected);
        }
        match timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => Ok(result?),
            Ok(Err(_)) => Err(RequestError::Disconnected),
            Err(_) => {
                self.forget(id);
                Err(RequestError::Timeout)
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Some(pending) = self.pending.lock().unwrap().as_mut() {
            pending.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use e2emes_proto::ErrorCode;

    use super::*;

    #[test]
    fn api_errors_print_once() {
        let e = anyhow::Error::from(crate::MessengerError::from(RequestError::Api(ApiError::new(
            ErrorCode::NotFound,
            "user carol not found",
        ))));
        assert_eq!(format!("{e:#}"), "user carol not found (NotFound)");
    }
}
