#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod upgrade;
pub mod websocket;

use std::fmt::Display;

use axum_core::body::Body;
use axum_core::response::IntoResponse;
use axum_core::response::Response;
use http::StatusCode;

pub use tokio_websockets::*;

pub use crate::{upgrade::WebSocketUpgrade, websocket::WebSocket};

#[derive(Debug)]
pub enum WebSocketError {
    ConnectionNotUpgradeable,
    Internal(tokio_websockets::Error),
    InvalidConnectionHeader,
    InvalidUpgradeHeader,
    InvalidWebSocketVersionHeader,
    MethodNotGet,
    UpgradeFailed(hyper::Error),
}

impl Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebSocket error: {}", self)
    }
}

impl std::error::Error for WebSocketError {}

impl IntoResponse for WebSocketError {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()
    }
}

impl From<tokio_websockets::Error> for WebSocketError {
    fn from(e: tokio_websockets::Error) -> Self {
        WebSocketError::Internal(e)
    }
}
