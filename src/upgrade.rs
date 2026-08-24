use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use axum_core::body::Body;
use axum_core::extract::FromRequestParts;
use axum_core::response::Response;
use http::request::Parts;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use sha1_smol::Sha1;
use task::{Handshake, UpgradeTask};
use tokio_websockets::{Config, Limits};

use crate::{websocket::WebSocket, WebSocketError};
pub use bounds::UpgradeExec;

mod task {
    use super::*;

    pin_project! {
        /// Await the handshake, build the socket, and run the callback on it.
        #[project = UpgradeTaskProj]
        pub enum UpgradeTask<C, Fut, F> {
            /// `handshake` temporarily becomes `None` during the handshake, and
            /// stays `None` on handshake failure.
            Handshaking { handshake: Option<Handshake<C, F>> },
            Running {
                #[pin]
                future: Fut,
            },
        }
    }

    pub struct Handshake<C, F> {
        pub on_upgrade: OnUpgrade,
        pub callback: C,
        pub config: Config,
        pub limits: Limits,
        pub protocol: Option<HeaderValue>,
        pub on_failed_upgrade: F,
    }

    impl<C, Fut, F> Future for UpgradeTask<C, Fut, F>
    where
        C: FnOnce(WebSocket) -> Fut,
        Fut: Future<Output = ()>,
        F: OnFailedUpgrade,
    {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            loop {
                let next = match self.as_mut().project() {
                    UpgradeTaskProj::Handshaking { handshake } => {
                        let pending = handshake
                            .as_mut()
                            .expect("`UpgradeTask` polled after completion");
                        let upgraded = ready!(Pin::new(&mut pending.on_upgrade).poll(cx));

                        let Handshake {
                            callback,
                            config,
                            limits,
                            protocol,
                            on_failed_upgrade,
                            ..
                        } = handshake.take().expect("`as_mut` above proved it is set");

                        match upgraded {
                            Ok(upgraded) => {
                                let stream = tokio_websockets::server::Builder::new()
                                    .config(config)
                                    .limits(limits)
                                    .serve(TokioIo::new(upgraded));
                                Self::Running {
                                    future: callback(WebSocket::new(stream, protocol)),
                                }
                            }
                            Err(err) => {
                                on_failed_upgrade.call(WebSocketError::UpgradeFailed(err));
                                return Poll::Ready(());
                            }
                        }
                    }
                    UpgradeTaskProj::Running { future } => {
                        return future.poll(cx);
                    }
                };

                self.as_mut().set(next);
            }
        }
    }
}

mod bounds {
    use super::{OnFailedUpgrade, UpgradeTask};
    use hyper::rt::Executor;

    /// An executor that can drive a WebSocket upgrade.
    ///
    /// Implemented automatically for every [`Executor`] that accepts this
    /// crate's private upgrade future, which is every executor generic over
    /// its future.
    ///
    /// [`Executor`]: hyper::rt::Executor
    pub trait UpgradeExec<C, Fut, F>: sealed::Sealed<(C, Fut, F)> {
        #[doc(hidden)]
        fn execute_upgrade(&self, task: UpgradeTask<C, Fut, F>);
    }

    impl<E, C, Fut, F> UpgradeExec<C, Fut, F> for E
    where
        E: Executor<UpgradeTask<C, Fut, F>>,
        F: OnFailedUpgrade,
    {
        fn execute_upgrade(&self, task: UpgradeTask<C, Fut, F>) {
            self.execute(task);
        }
    }

    mod sealed {
        use super::{Executor, OnFailedUpgrade, UpgradeTask};

        pub trait Sealed<T> {}

        impl<E, C, Fut, F> Sealed<(C, Fut, F)> for E
        where
            E: Executor<UpgradeTask<C, Fut, F>>,
            F: OnFailedUpgrade,
        {
        }
    }
}

pub trait OnFailedUpgrade: Send + 'static {
    fn call(self, error: WebSocketError);
}

impl<F> OnFailedUpgrade for F
where
    F: FnOnce(WebSocketError) + Send + 'static,
{
    fn call(self, error: WebSocketError) {
        self(error)
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub struct DefaultOnFailedUpgrade;

impl OnFailedUpgrade for DefaultOnFailedUpgrade {
    #[inline]
    fn call(self, _error: WebSocketError) {}
}

pub struct WebSocketUpgrade<F = DefaultOnFailedUpgrade> {
    config: Config,
    limits: Limits,
    protocol: Option<HeaderValue>,
    /// `None` if HTTP/2+ WebSockets are used.
    sec_websocket_key: Option<HeaderValue>,
    on_upgrade: hyper::upgrade::OnUpgrade,
    on_failed_upgrade: F,
    sec_websocket_protocol: Option<HeaderValue>,
}

impl<F> std::fmt::Debug for WebSocketUpgrade<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketUpgrade")
            .field("config", &self.config)
            .field("protocol", &self.protocol)
            .field("sec_websocket_key", &self.sec_websocket_key)
            .field("sec_websocket_protocol", &self.sec_websocket_protocol)
            .finish_non_exhaustive()
    }
}

impl<S> FromRequestParts<S> for WebSocketUpgrade<DefaultOnFailedUpgrade>
where
    S: Send + Sync,
{
    type Rejection = WebSocketError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let sec_websocket_key = if parts.version <= Version::HTTP_11 || cfg!(not(feature = "http2"))
        {
            if parts.method != Method::GET {
                return Err(WebSocketError::MethodNotGet);
            }

            if !header_contains(&parts.headers, header::CONNECTION, "upgrade") {
                return Err(WebSocketError::InvalidConnectionHeader);
            }

            if !header_eq(&parts.headers, header::UPGRADE, "websocket") {
                return Err(WebSocketError::InvalidUpgradeHeader);
            }

            let sec_websocket_key = parts
                .headers
                .get(header::SEC_WEBSOCKET_KEY)
                .ok_or(WebSocketError::InvalidWebSocketVersionHeader)?
                .clone();

            Some(sec_websocket_key)
        } else {
            if parts.method != Method::CONNECT {
                return Err(WebSocketError::MethodNotConnect);
            }

            // if this feature flag is disabled, we won’t be receiving an HTTP/2 request to begin
            // with.
            #[cfg(feature = "http2")]
            if parts
                .extensions
                .get::<hyper::ext::Protocol>()
                .is_none_or(|p| p.as_str() != "websocket")
            {
                return Err(WebSocketError::InvalidProtocolPseudoheader);
            }

            None
        };

        if !header_eq(&parts.headers, header::SEC_WEBSOCKET_VERSION, "13") {
            return Err(WebSocketError::InvalidWebSocketVersionHeader);
        }

        let on_upgrade = parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or(WebSocketError::ConnectionNotUpgradeable)?;

        let sec_websocket_protocol = parts.headers.get(header::SEC_WEBSOCKET_PROTOCOL).cloned();

        Ok(Self {
            config: Default::default(),
            limits: Default::default(),
            protocol: None,
            sec_websocket_key,
            on_upgrade,
            sec_websocket_protocol,
            on_failed_upgrade: DefaultOnFailedUpgrade,
        })
    }
}

impl<F> WebSocketUpgrade<F> {
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn on_failed_upgrade<C>(self, callback: C) -> WebSocketUpgrade<C>
    where
        C: OnFailedUpgrade,
    {
        WebSocketUpgrade {
            config: self.config,
            limits: self.limits,
            protocol: self.protocol,
            sec_websocket_key: self.sec_websocket_key,
            on_upgrade: self.on_upgrade,
            on_failed_upgrade: callback,
            sec_websocket_protocol: self.sec_websocket_protocol,
        }
    }

    /// Completes the upgrade, driving the socket on the Tokio runtime.
    ///
    /// Equivalent to [`Self::on_upgrade_with`] given a
    /// [`hyper_util::rt::TokioExecutor`].
    #[must_use = "to set up the WebSocket connection, this response must be returned"]
    pub fn on_upgrade<C, Fut>(self, callback: C) -> Response
    where
        C: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        F: OnFailedUpgrade,
    {
        self.on_upgrade_with(hyper_util::rt::TokioExecutor::new(), callback)
    }

    /// Completes the upgrade, driving the socket on `executor`.
    #[must_use = "to set up the WebSocket connection, this response must be returned"]
    pub fn on_upgrade_with<E, C, Fut>(self, executor: E, callback: C) -> Response
    where
        E: UpgradeExec<C, Fut, F>,
        C: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        F: OnFailedUpgrade,
    {
        executor.execute_upgrade(UpgradeTask::Handshaking {
            handshake: Some(Handshake {
                on_upgrade: self.on_upgrade,
                callback,
                config: self.config,
                limits: self.limits,
                protocol: self.protocol.clone(),
                on_failed_upgrade: self.on_failed_upgrade,
            }),
        });

        let mut response = if let Some(sec_websocket_key) = &self.sec_websocket_key {
            // If `sec_websocket_key` was `Some`, we are using HTTP/1.1.

            #[allow(clippy::declare_interior_mutable_const)]
            const UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
            #[allow(clippy::declare_interior_mutable_const)]
            const WEBSOCKET: HeaderValue = HeaderValue::from_static("websocket");

            let builder = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, UPGRADE)
                .header(header::UPGRADE, WEBSOCKET)
                .header(
                    header::SEC_WEBSOCKET_ACCEPT,
                    sign(sec_websocket_key.as_bytes()),
                );

            builder.body(Body::empty()).unwrap()
        } else {
            // Otherwise, we are HTTP/2+. As established in RFC 9113 section 8.5, we just respond
            // with a 2XX with an empty body:
            // <https://datatracker.ietf.org/doc/html/rfc9113#name-the-connect-method>.
            Response::new(Body::empty())
        };

        if let Some(protocol) = self.protocol {
            response
                .headers_mut()
                .insert(header::SEC_WEBSOCKET_PROTOCOL, protocol);
        }

        response
    }
}

fn sign(key: &[u8]) -> HeaderValue {
    use base64::engine::Engine as _;

    let mut sha1 = Sha1::default();
    sha1.update(key);
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Accept
    sha1.update(&b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"[..]);
    let b64 =
        bytes::Bytes::from(base64::engine::general_purpose::STANDARD.encode(sha1.digest().bytes()));
    HeaderValue::from_maybe_shared(b64).expect("base64 is a valid value")
}

fn header_contains(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    let header = if let Some(header) = headers.get(&key) {
        header
    } else {
        return false;
    };

    if let Ok(header) = std::str::from_utf8(header.as_bytes()) {
        header.to_ascii_lowercase().contains(value)
    } else {
        false
    }
}

fn header_eq(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    if let Some(header) = headers.get(&key) {
        header.as_bytes().eq_ignore_ascii_case(value.as_bytes())
    } else {
        false
    }
}
