//! `/v1/stream` WebSocket client: tokio-tungstenite over rustls (ring
//! provider, webpki roots), bearer auth, JSON text frames.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use gim_proto::dto::{
    paths, StreamFrame, CURSOR_EXPIRED, STREAM_CLOSE_CURSOR_EXPIRED, STREAM_CLOSE_UNAUTHORIZED,
};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderValue, AUTHORIZATION};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::http::HttpTransport;
use crate::transport::{AccessToken, EventBatch, EventStream, TransportError, TransportResult};

/// A ping is sent after this long without a frame.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// The connection counts as dead after this long without a frame.
const IDLE_TIMEOUT: Duration = Duration::from_secs(75);

/// `ws(s)://…/v1/stream[?cursor=N]` for an `http(s)://…` base URL without a
/// trailing `/`.
pub(crate) fn stream_url(base_url: &str, cursor: Option<u64>) -> TransportResult<String> {
    let (scheme, rest) = if let Some(rest) = base_url.strip_prefix("https://") {
        ("wss://", rest)
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        ("ws://", rest)
    } else {
        return Err(TransportError::Network(format!(
            "unsupported base URL scheme: {base_url}"
        )));
    };
    let mut url = format!("{scheme}{rest}{}", paths::STREAM);
    if let Some(cursor) = cursor {
        url.push_str(&format!("?cursor={cursor}"));
    }
    Ok(url)
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn network(err: tungstenite::Error) -> TransportError {
    TransportError::Network(format!("stream: {err}"))
}

/// An open `/v1/stream` connection. Events are converted by the
/// [`HttpTransport`] that opened it, which shares its device directory.
pub(crate) struct WsEventStream {
    transport: HttpTransport,
    token: AccessToken,
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    last_frame: Instant,
}

impl WsEventStream {
    /// Connects within `timeout`. `Ok(None)` if the server refuses the
    /// upgrade with a status other than 401: it has no stream.
    pub(crate) async fn connect(
        transport: HttpTransport,
        token: AccessToken,
        url: String,
        timeout: Duration,
    ) -> TransportResult<Option<Self>> {
        let mut request = url.into_client_request().map_err(network)?;
        let bearer = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
            .map_err(|_| TransportError::Unauthorized)?;
        request.headers_mut().insert(AUTHORIZATION, bearer);
        let connecting = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(tls_config())),
        );
        let socket = match tokio::time::timeout(timeout, connecting).await {
            Err(_) => return Err(TransportError::Network("stream: connect timed out".into())),
            Ok(Ok((socket, _))) => socket,
            Ok(Err(tungstenite::Error::Http(response))) => {
                if response.status() == StatusCode::UNAUTHORIZED {
                    return Err(TransportError::Unauthorized);
                }
                tracing::debug!(status = %response.status(), "stream upgrade refused");
                return Ok(None);
            }
            Ok(Err(err)) => return Err(network(err)),
        };
        Ok(Some(Self {
            transport,
            token,
            socket,
            last_frame: Instant::now(),
        }))
    }

    async fn on_text(&mut self, text: &str) -> TransportResult<Option<EventBatch>> {
        match serde_json::from_str::<StreamFrame>(text) {
            Ok(StreamFrame::Event { event }) => {
                let next_cursor = event.cursor;
                let events = self
                    .transport
                    .convert_events(&self.token, vec![event])
                    .await?;
                Ok(Some(EventBatch {
                    events,
                    next_cursor,
                }))
            }
            Ok(StreamFrame::Error {
                error,
                cursor: Some(cursor),
            }) if error.code == CURSOR_EXPIRED => Err(TransportError::Gone { cursor }),
            Ok(StreamFrame::Error { error, .. }) => Err(TransportError::Server(format!(
                "stream: {}: {}",
                error.code, error.message
            ))),
            Ok(StreamFrame::Unknown) => Ok(None),
            Err(err) => Err(TransportError::Server(format!(
                "stream: invalid frame: {err}"
            ))),
        }
    }
}

fn close_error(code: Option<u16>) -> TransportError {
    match code {
        Some(STREAM_CLOSE_UNAUTHORIZED) => TransportError::Unauthorized,
        // The head cursor comes in the error frame before the close; without
        // it the next `fetch_events` reports the expiry with the head.
        Some(STREAM_CLOSE_CURSOR_EXPIRED) => {
            TransportError::Network("stream: cursor expired".into())
        }
        code => TransportError::Network(format!("stream: closed by server ({code:?})")),
    }
}

#[async_trait]
impl EventStream for WsEventStream {
    async fn next(&mut self) -> TransportResult<EventBatch> {
        loop {
            let frame = tokio::select! {
                frame = self.socket.next() => frame,
                () = tokio::time::sleep(PING_INTERVAL) => {
                    if self.last_frame.elapsed() >= IDLE_TIMEOUT {
                        return Err(TransportError::Network("stream: idle timeout".into()));
                    }
                    self.socket
                        .send(Message::Ping(Default::default()))
                        .await
                        .map_err(network)?;
                    continue;
                }
            };
            let Some(frame) = frame else {
                return Err(TransportError::Network("stream: connection ended".into()));
            };
            let message = frame.map_err(network)?;
            self.last_frame = Instant::now();
            match message {
                Message::Text(text) => {
                    if let Some(batch) = self.on_text(text.as_str()).await? {
                        return Ok(batch);
                    }
                }
                Message::Close(frame) => {
                    return Err(close_error(frame.map(|f| u16::from(f.code))));
                }
                // Pings are answered by tungstenite; binary frames are not
                // part of the protocol.
                _ => {}
            }
        }
    }
}
