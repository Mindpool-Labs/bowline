use std::{convert::Infallible, env};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::OriginalUri,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use futures_util::stream;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listen = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9999".to_string());
    let listener = TcpListener::bind(&listen).await?;

    tracing::info!(listen = %listener.local_addr()?, "echo upstream listening");
    axum::serve(listener, Router::new().fallback(any(echo_handler))).await?;

    Ok(())
}

async fn echo_handler(
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let body = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    if uri.path() == "/v1/chat/completions" {
        if request_is_streaming(&body) {
            return sse_response();
        }

        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":5}}"#,
        )
            .into_response();
    }

    if uri.path() == "/v1/models" {
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"object":"list","data":[{"id":"gpt-5-mini"}]}"#,
        )
            .into_response();
    }

    let _ = headers;
    (StatusCode::OK, r#"{"echo":true}"#).into_response()
}

fn request_is_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}

fn sse_response() -> Response<Body> {
    let chunks = [
        Bytes::from_static(br#"data: {"choices":[{"delta":{"content":"one"}}]}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(br#"data: {"choices":[{"delta":{"content":"two"}}]}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(br#"data: {"usage":{"prompt_tokens":7,"completion_tokens":5}}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(b"data: [DONE]\n\n"),
    ];
    let stream = stream::iter(chunks.map(Ok::<Bytes, Infallible>));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("static SSE response builds")
}
