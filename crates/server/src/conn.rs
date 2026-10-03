//! One client connection: handshake, request loop and pushed events.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use e2emes_proto::{
    is_valid_name,
    transport::{server_handshake, TransportError},
    ApiError, ChatList, ClientFrame, ErrorCode, Event, PublicKey, Request, Response, ServerFrame, StoredMessage,
    UserInfo, MAX_CIPHERTEXT_LEN, MAX_SYNC_LIMIT, MIN_PASSWORD_LEN, NONCE_LEN,
};
use tokio::{net::TcpStream, sync::mpsc, time::timeout};
use tracing::{debug, error, info};

use crate::{
    auth,
    db::{self, UserRow},
    hub::ConnId,
    Shared,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// An unauthenticated connection has this long between requests.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// Clients ping every 30 seconds; a silent connection is dropped after this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Failed `Login`/`Resume` attempts allowed on one connection before it's closed.
const MAX_AUTH_FAILURES: u32 = 3;
/// Pending frames per connection.
const QUEUE_LEN: usize = 256;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

type ApiResult = Result<Response, ApiError>;

fn err(code: ErrorCode, message: impl Into<String>) -> ApiError {
    ApiError::new(code, message)
}

fn internal(e: anyhow::Error) -> ApiError {
    error!("internal error: {e:#}");
    err(ErrorCode::Internal, "internal server error")
}

#[derive(Clone)]
struct CurrentUser {
    id: i64,
    name: String,
    identity_key: PublicKey,
}

struct Session {
    conn: ConnId,
    peer: SocketAddr,
    tx: mpsc::Sender<ServerFrame>,
    user: Option<CurrentUser>,
    token_hash: Option<[u8; 32]>,
    auth_failures: u32,
    close: bool,
}

pub async fn handle(stream: TcpStream, peer: SocketAddr, shared: Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = match timeout(HANDSHAKE_TIMEOUT, server_handshake(stream, &shared.private_key)).await
    {
        Ok(Ok(halves)) => halves,
        Ok(Err(e)) => return debug!("{peer}: handshake failed: {e}"),
        Err(_) => return debug!("{peer}: handshake timed out"),
    };

    let (tx, mut rx) = mpsc::channel::<ServerFrame>(QUEUE_LEN);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Err(e) = writer.send(&frame).await {
                debug!("write failed: {e}");
                break;
            }
        }
        writer.shutdown().await;
    });

    let mut session = Session {
        conn: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
        peer,
        tx: tx.clone(),
        user: None,
        token_hash: None,
        auth_failures: 0,
        close: false,
    };

    loop {
        let limit = if session.user.is_some() {
            IDLE_TIMEOUT
        } else {
            AUTH_TIMEOUT
        };
        let frame: ClientFrame = match timeout(limit, reader.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(TransportError::Closed)) => break,
            Ok(Err(e)) => {
                debug!("{peer}: dropping connection: {e}");
                break;
            }
            Err(_) => {
                debug!("{peer}: idle timeout");
                break;
            }
        };
        let result = session.handle(&shared, frame.request).await;
        if tx.send(ServerFrame::Response { id: frame.id, result }).await.is_err() || session.close {
            break;
        }
    }

    session.disconnect(&shared).await;
    drop(session);
    drop(tx);
    // Let queued frames (e.g. the last response) go out before closing.
    let _ = timeout(Duration::from_secs(5), writer_task).await;
}

fn user_info(shared: &Shared, row: &UserRow) -> UserInfo {
    UserInfo {
        name: row.name.clone(),
        identity_key: row.identity_key,
        online: shared.hub.is_online(row.id),
    }
}

impl Session {
    async fn handle(&mut self, s: &Shared, request: Request) -> ApiResult {
        match request {
            Request::Ping => Ok(Response::Pong),
            Request::Register { .. } | Request::Login { .. } | Request::Resume { .. } if self.user.is_some() => {
                Err(err(ErrorCode::AlreadyAuthenticated, "already logged in"))
            }
            Request::Register {
                name,
                password,
                identity_key,
            } => self.register(s, name, password, identity_key).await,
            Request::Login { name, password } => self.login(s, name, password).await,
            Request::Resume { token } => self.resume(s, token).await,
            other => {
                let user = self
                    .user
                    .clone()
                    .ok_or_else(|| err(ErrorCode::Unauthorized, "log in first"))?;
                match other {
                    Request::Logout => self.logout(s).await,
                    Request::LookupUser { name } => self.lookup(s, name).await,
                    Request::RequestChat { name } => self.request_chat(s, &user, name).await,
                    Request::RespondChat { name, accept } => self.respond_chat(s, &user, name, accept).await,
                    Request::ListChats => self.list_chats(s, &user).await,
                    Request::SendMessage { to, nonce, ciphertext } => {
                        self.send_message(s, &user, to, nonce, ciphertext).await
                    }
                    Request::Sync { after_id, limit } => self.sync(s, &user, after_id, limit).await,
                    Request::Ping | Request::Register { .. } | Request::Login { .. } | Request::Resume { .. } => {
                        unreachable!("handled above")
                    }
                }
            }
        }
    }

    async fn register(&mut self, s: &Shared, name: String, password: String, identity_key: PublicKey) -> ApiResult {
        if !is_valid_name(&name) {
            return Err(err(
                ErrorCode::InvalidName,
                "name must be 3-32 characters of A-Z, a-z, 0-9, _ or -",
            ));
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(err(
                ErrorCode::WeakPassword,
                format!("password must have at least {MIN_PASSWORD_LEN} characters"),
            ));
        }
        if identity_key.0 == [0u8; 32] {
            return Err(err(ErrorCode::BadRequest, "invalid identity key"));
        }

        let hash = {
            let _permit = s.kdf.acquire().await.map_err(|e| internal(e.into()))?;
            tokio::task::spawn_blocking(move || auth::hash_password(&password))
                .await
                .map_err(|e| internal(e.into()))?
                .map_err(internal)?
        };

        let (token, token_hash) = auth::new_token();
        let user_name = name.clone();
        let created =
            s.db.call(move |c| {
                let tx = c.transaction()?;
                let Some(id) = db::insert_user(&tx, &user_name, &hash, &identity_key)? else {
                    return Ok(None);
                };
                db::insert_session(&tx, &token_hash, id, db::now() + auth::SESSION_TTL.as_secs() as i64)?;
                tx.commit()?;
                Ok(Some(id))
            })
            .await
            .map_err(internal)?;
        let Some(id) = created else {
            return Err(err(ErrorCode::NameTaken, format!("name {name} is already taken")));
        };

        info!("{}: registered {name}", self.peer);
        self.authenticate(
            s,
            CurrentUser {
                id,
                name: name.clone(),
                identity_key,
            },
            token_hash,
        )
        .await;
        Ok(Response::Authenticated {
            name,
            token,
            identity_key,
        })
    }

    async fn login(&mut self, s: &Shared, name: String, password: String) -> ApiResult {
        let ip = self.peer.ip();
        if !s.limiter.allowed(ip) {
            self.close = true;
            return Err(err(
                ErrorCode::TooManyAttempts,
                "too many failed logins, try again later",
            ));
        }

        let lookup = name.clone();
        let row =
            s.db.call(move |c| db::user_by_name(c, &lookup))
                .await
                .map_err(internal)?;
        let stored = row.as_ref().map(|r| r.password_hash.clone());
        let ok = {
            let _permit = s.kdf.acquire().await.map_err(|e| internal(e.into()))?;
            tokio::task::spawn_blocking(move || auth::verify_password(&password, stored.as_deref()))
                .await
                .map_err(|e| internal(e.into()))?
        };

        let row = match (ok, row) {
            (true, Some(row)) => row,
            _ => {
                s.limiter.record_failure(ip);
                self.auth_failed();
                info!("{}: failed login for {name}", self.peer);
                return Err(err(ErrorCode::InvalidCredentials, "wrong name or password"));
            }
        };

        let (token, token_hash) = auth::new_token();
        let user_id = row.id;
        s.db.call(move |c| {
            db::delete_expired_sessions(c, db::now())?;
            db::insert_session(c, &token_hash, user_id, db::now() + auth::SESSION_TTL.as_secs() as i64)
        })
        .await
        .map_err(internal)?;

        info!("{}: {} logged in", self.peer, row.name);
        self.authenticate(
            s,
            CurrentUser {
                id: row.id,
                name: row.name.clone(),
                identity_key: row.identity_key,
            },
            token_hash,
        )
        .await;
        Ok(Response::Authenticated {
            name: row.name,
            token,
            identity_key: row.identity_key,
        })
    }

    async fn resume(&mut self, s: &Shared, token: String) -> ApiResult {
        let token_hash = auth::token_hash(&token);
        let row =
            s.db.call(move |c| match db::session_user(c, &token_hash)? {
                Some(id) => db::user_by_id(c, id),
                None => Ok(None),
            })
            .await
            .map_err(internal)?;
        let Some(row) = row else {
            self.auth_failed();
            return Err(err(
                ErrorCode::Unauthorized,
                "session expired or revoked, log in with your password",
            ));
        };

        self.authenticate(
            s,
            CurrentUser {
                id: row.id,
                name: row.name.clone(),
                identity_key: row.identity_key,
            },
            token_hash,
        )
        .await;
        Ok(Response::Authenticated {
            name: row.name,
            token,
            identity_key: row.identity_key,
        })
    }

    fn auth_failed(&mut self) {
        self.auth_failures += 1;
        if self.auth_failures >= MAX_AUTH_FAILURES {
            self.close = true;
        }
    }

    async fn authenticate(&mut self, s: &Shared, user: CurrentUser, token_hash: [u8; 32]) {
        let came_online = s.hub.attach(user.id, self.conn, self.tx.clone());
        if came_online {
            self.broadcast_presence(s, &user, true).await;
        }
        self.user = Some(user);
        self.token_hash = Some(token_hash);
    }

    async fn broadcast_presence(&self, s: &Shared, user: &CurrentUser, online: bool) {
        let id = user.id;
        let partners = match s.db.call(move |c| db::chat_partners(c, id)).await {
            Ok(partners) => partners,
            Err(e) => return error!("presence lookup failed: {e:#}"),
        };
        let frame = ServerFrame::Event(Event::Presence {
            name: user.name.clone(),
            online,
        });
        for partner in partners {
            s.hub.send(partner.id, &frame, None);
        }
    }

    async fn disconnect(&mut self, s: &Shared) {
        if let Some(user) = self.user.take() {
            if s.hub.detach(user.id, self.conn) {
                self.broadcast_presence(s, &user, false).await;
            }
        }
    }

    async fn logout(&mut self, s: &Shared) -> ApiResult {
        if let Some(hash) = self.token_hash.take() {
            s.db.call(move |c| db::delete_session(c, &hash))
                .await
                .map_err(internal)?;
        }
        self.close = true;
        Ok(Response::Ok)
    }

    async fn find_user(&self, s: &Shared, name: String) -> Result<UserRow, ApiError> {
        if !is_valid_name(&name) {
            return Err(err(ErrorCode::InvalidName, "invalid user name"));
        }
        let lookup = name.clone();
        s.db.call(move |c| db::user_by_name(c, &lookup))
            .await
            .map_err(internal)?
            .ok_or_else(|| err(ErrorCode::NotFound, format!("user {name} not found")))
    }

    async fn lookup(&self, s: &Shared, name: String) -> ApiResult {
        let row = self.find_user(s, name).await?;
        Ok(Response::User(user_info(s, &row)))
    }

    async fn request_chat(&self, s: &Shared, me: &CurrentUser, name: String) -> ApiResult {
        let target = self.find_user(s, name).await?;
        if target.id == me.id {
            return Err(err(ErrorCode::BadRequest, "can't open a chat with yourself"));
        }

        enum Outcome {
            AlreadyOpen,
            OpenedByCounterRequest,
            Requested,
        }
        let (my_id, target_id) = (me.id, target.id);
        let outcome =
            s.db.call(move |c| {
                let tx = c.transaction()?;
                let outcome = if db::chat_exists(&tx, my_id, target_id)? {
                    Outcome::AlreadyOpen
                } else if db::delete_request(&tx, target_id, my_id)? {
                    // They already asked us: treat our request as acceptance.
                    db::insert_chat(&tx, my_id, target_id)?;
                    Outcome::OpenedByCounterRequest
                } else {
                    db::insert_request(&tx, my_id, target_id)?;
                    Outcome::Requested
                };
                tx.commit()?;
                Ok(outcome)
            })
            .await
            .map_err(internal)?;

        let me_info = UserInfo {
            name: me.name.clone(),
            identity_key: me.identity_key,
            online: true,
        };
        let open = match outcome {
            Outcome::AlreadyOpen => true,
            Outcome::OpenedByCounterRequest => {
                s.hub
                    .send(target.id, &ServerFrame::Event(Event::ChatAccepted(me_info)), None);
                true
            }
            Outcome::Requested => {
                s.hub
                    .send(target.id, &ServerFrame::Event(Event::ChatRequest(me_info)), None);
                false
            }
        };
        Ok(Response::ChatStatus {
            user: user_info(s, &target),
            open,
        })
    }

    async fn respond_chat(&self, s: &Shared, me: &CurrentUser, name: String, accept: bool) -> ApiResult {
        let requester = self.find_user(s, name).await?;
        let (my_id, requester_id) = (me.id, requester.id);
        let had_request =
            s.db.call(move |c| {
                let tx = c.transaction()?;
                // Only a request that really exists can be answered: a client can't
                // force a chat with someone who never asked.
                let had_request = db::delete_request(&tx, requester_id, my_id)?;
                if had_request && accept {
                    db::insert_chat(&tx, requester_id, my_id)?;
                }
                tx.commit()?;
                Ok(had_request)
            })
            .await
            .map_err(internal)?;
        if !had_request {
            return Err(err(
                ErrorCode::NotFound,
                format!("no pending chat request from {}", requester.name),
            ));
        }

        if accept {
            let me_info = UserInfo {
                name: me.name.clone(),
                identity_key: me.identity_key,
                online: true,
            };
            s.hub
                .send(requester.id, &ServerFrame::Event(Event::ChatAccepted(me_info)), None);
        }
        Ok(Response::ChatStatus {
            user: user_info(s, &requester),
            open: accept,
        })
    }

    async fn list_chats(&self, s: &Shared, me: &CurrentUser) -> ApiResult {
        let id = me.id;
        let (chats, incoming, outgoing) =
            s.db.call(move |c| {
                Ok((
                    db::chat_partners(c, id)?,
                    db::incoming_requests(c, id)?,
                    db::outgoing_requests(c, id)?,
                ))
            })
            .await
            .map_err(internal)?;
        Ok(Response::Chats(ChatList {
            chats: chats.iter().map(|r| user_info(s, r)).collect(),
            incoming: incoming.iter().map(|r| user_info(s, r)).collect(),
            outgoing: outgoing.into_iter().map(|r| r.name).collect(),
        }))
    }

    async fn send_message(
        &self,
        s: &Shared,
        me: &CurrentUser,
        to: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> ApiResult {
        if nonce.len() != NONCE_LEN || ciphertext.len() < 16 {
            return Err(err(ErrorCode::BadRequest, "malformed ciphertext"));
        }
        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(err(
                ErrorCode::TooLarge,
                format!("message is larger than {MAX_CIPHERTEXT_LEN} bytes"),
            ));
        }
        let target = self.find_user(s, to).await?;

        let (my_id, target_id) = (me.id, target.id);
        let (stored_nonce, stored_ct) = (nonce.clone(), ciphertext.clone());
        let inserted =
            s.db.call(move |c| {
                if !db::chat_exists(c, my_id, target_id)? {
                    return Ok(None);
                }
                db::insert_message(c, my_id, target_id, &stored_nonce, &stored_ct).map(Some)
            })
            .await
            .map_err(internal)?;
        let Some((id, timestamp)) = inserted else {
            return Err(err(
                ErrorCode::NotAChat,
                format!("you have no chat with {}", target.name),
            ));
        };

        let frame = ServerFrame::Event(Event::NewMessage(StoredMessage {
            id,
            from: me.name.clone(),
            to: target.name.clone(),
            timestamp,
            nonce,
            ciphertext,
        }));
        s.hub.send(target.id, &frame, None);
        // The sender's other devices get a copy too.
        s.hub.send(me.id, &frame, Some(self.conn));
        Ok(Response::MessageAccepted { id, timestamp })
    }

    async fn sync(&self, s: &Shared, me: &CurrentUser, after_id: i64, limit: u32) -> ApiResult {
        let limit = limit.clamp(1, MAX_SYNC_LIMIT);
        let id = me.id;
        let mut messages =
            s.db.call(move |c| db::messages_after(c, id, after_id, limit + 1))
                .await
                .map_err(internal)?;
        let more = messages.len() > limit as usize;
        messages.truncate(limit as usize);
        Ok(Response::Messages { messages, more })
    }
}
