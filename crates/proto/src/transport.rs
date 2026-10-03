//! Encrypted, authenticated framing over TCP.
//!
//! The client runs a Noise `NK` handshake against the server's static key, which
//! it must know in advance (the `server.pub` file). This gives
//! - server authentication: only the holder of the server's private key can finish the handshake;
//! - forward secrecy: transport keys come from fresh ephemeral keys;
//! - replay and reorder protection: every frame uses the next nonce of a counter,
//!   so a repeated, dropped or reordered frame fails to decrypt.
//!
//! On the wire each Noise message is prefixed with its length as a big-endian `u32`.

use std::{io, sync::Arc};

use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, HandshakeState, StatelessTransportState};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

pub const NOISE_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
/// Noise limits a single message to 65535 bytes, including the 16-byte tag.
pub const MAX_FRAME_LEN: usize = 65535;
const TAG_LEN: usize = 16;
/// Binds the handshake to this protocol version.
const PROLOGUE: &[u8] = b"E2EMes/2";

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection closed")]
    Closed,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("frame of {0} bytes is too large")]
    FrameTooLarge(usize),
    #[error("malformed frame: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// A static X25519 key pair of the server.
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl StaticKeypair {
    pub fn generate() -> Result<Self> {
        let keypair = Builder::new(NOISE_PARAMS.parse().expect("valid noise params")).generate_keypair()?;
        Ok(Self {
            private: keypair.private.try_into().expect("32-byte key"),
            public: keypair.public.try_into().expect("32-byte key"),
        })
    }

    /// Recomputes the public half from a stored private key.
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_base(&private);
        Self { private, public }
    }
}

/// X25519 public key of `private`, computed with snow's own DH implementation.
fn x25519_base(private: &[u8; 32]) -> [u8; 32] {
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};

    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("curve25519 is supported");
    dh.set(private);
    dh.pubkey().try_into().expect("32-byte key")
}

async fn write_raw(w: &mut OwnedWriteHalf, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_LEN {
        return Err(TransportError::FrameTooLarge(data.len()));
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    w.write_all(&out).await?;
    Ok(())
}

async fn read_raw(r: &mut OwnedReadHalf) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(TransportError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(TransportError::FrameTooLarge(len));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await.map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => TransportError::Closed,
        _ => e.into(),
    })?;
    Ok(data)
}

/// Runs the initiator side of the handshake. Fails unless the peer holds the
/// private key matching `server_public`.
pub async fn client_handshake(stream: TcpStream, server_public: &[u8; 32]) -> Result<(NoiseReader, NoiseWriter)> {
    let mut hs = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
        .prologue(PROLOGUE)
        .remote_public_key(server_public)
        .build_initiator()?;
    let (mut r, mut w) = stream.into_split();
    let mut buf = vec![0u8; MAX_FRAME_LEN];

    let n = hs.write_message(&[], &mut buf)?;
    write_raw(&mut w, &buf[..n]).await?;
    let reply = read_raw(&mut r).await?;
    hs.read_message(&reply, &mut buf)?;

    finish(hs, r, w)
}

/// Runs the responder side of the handshake with the server's static private key.
pub async fn server_handshake(stream: TcpStream, private: &[u8; 32]) -> Result<(NoiseReader, NoiseWriter)> {
    let mut hs = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
        .prologue(PROLOGUE)
        .local_private_key(private)
        .build_responder()?;
    let (mut r, mut w) = stream.into_split();
    let mut buf = vec![0u8; MAX_FRAME_LEN];

    let hello = read_raw(&mut r).await?;
    hs.read_message(&hello, &mut buf)?;
    let n = hs.write_message(&[], &mut buf)?;
    write_raw(&mut w, &buf[..n]).await?;

    finish(hs, r, w)
}

fn finish(hs: HandshakeState, r: OwnedReadHalf, w: OwnedWriteHalf) -> Result<(NoiseReader, NoiseWriter)> {
    // The stateless mode takes explicit nonces, which lets the two directions live in
    // separate tasks. Each side still uses strictly increasing counters.
    let state = Arc::new(hs.into_stateless_transport_mode()?);
    Ok((
        NoiseReader {
            half: r,
            state: state.clone(),
            nonce: 0,
            buf: vec![0u8; MAX_FRAME_LEN],
        },
        NoiseWriter {
            half: w,
            state,
            nonce: 0,
            buf: vec![0u8; MAX_FRAME_LEN],
        },
    ))
}

pub struct NoiseReader {
    half: OwnedReadHalf,
    state: Arc<StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
}

impl NoiseReader {
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let raw = read_raw(&mut self.half).await?;
        let n = self.state.read_message(self.nonce, &raw, &mut self.buf)?;
        self.nonce += 1;
        Ok(serde_json::from_slice(&self.buf[..n])?)
    }
}

pub struct NoiseWriter {
    half: OwnedWriteHalf,
    state: Arc<StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
}

impl NoiseWriter {
    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let plain = serde_json::to_vec(msg)?;
        if plain.len() + TAG_LEN > MAX_FRAME_LEN {
            return Err(TransportError::FrameTooLarge(plain.len()));
        }
        let n = self.state.write_message(self.nonce, &plain, &mut self.buf)?;
        self.nonce += 1;
        write_raw(&mut self.half, &self.buf[..n]).await
    }

    pub async fn shutdown(&mut self) {
        let _ = self.half.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair(
        server_key: StaticKeypair,
        client_view: [u8; 32],
    ) -> (Result<(NoiseReader, NoiseWriter)>, Result<(NoiseReader, NoiseWriter)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_handshake(stream, &server_key.private).await
        });
        let client = client_handshake(TcpStream::connect(addr).await.unwrap(), &client_view).await;
        (client, server.await.unwrap())
    }

    #[tokio::test]
    async fn frames_flow_both_ways() {
        let key = StaticKeypair::generate().unwrap();
        let public = key.public;
        let (client, server) = pair(key, public).await;
        let (mut cr, mut cw) = client.unwrap();
        let (mut sr, mut sw) = server.unwrap();

        for i in 0..3u32 {
            cw.send(&format!("ping {i}")).await.unwrap();
            assert_eq!(sr.recv::<String>().await.unwrap(), format!("ping {i}"));
            sw.send(&i).await.unwrap();
            assert_eq!(cr.recv::<u32>().await.unwrap(), i);
        }

        let big = "x".repeat(MAX_FRAME_LEN);
        assert!(matches!(cw.send(&big).await, Err(TransportError::FrameTooLarge(_))));
    }

    #[tokio::test]
    async fn wrong_server_key_fails() {
        let key = StaticKeypair::generate().unwrap();
        let other = StaticKeypair::generate().unwrap().public;
        let (client, server) = pair(key, other).await;
        // The responder can't decrypt the initiator's `es` payload, so it rejects;
        // the client then sees the connection close.
        assert!(server.is_err());
        assert!(client.is_err());
    }

    #[test]
    fn public_key_derivation_matches() {
        let key = StaticKeypair::generate().unwrap();
        assert_eq!(StaticKeypair::from_private(key.private).public, key.public);
    }
}
