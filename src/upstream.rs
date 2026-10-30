//! Minimal herdr JSON API client (one request per connection).

use std::path::Path;

use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio::net::UnixStream;

use crate::protocol;

pub async fn request(
    socket: &Path,
    method: &str,
    params: Value,
    id_prefix: &str,
) -> Result<Value, String> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|error| format!("connect {}: {error}", socket.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let id = format!("{id_prefix}-{}", crate::jwt::random_id());
    let request = json!({ "id": id, "method": method, "params": params });
    let line =
        serde_json::to_string(&request).map_err(|error| format!("encode request: {error}"))?;
    protocol::write_line(&mut write_half, &line)
        .await
        .map_err(|error| format!("write request: {error}"))?;

    let response = protocol::read_line(&mut reader)
        .await
        .map_err(|error| format!("read response: {error}"))?
        .ok_or_else(|| "upstream closed without a response".to_string())?;
    let value: Value = serde_json::from_str(&response)
        .map_err(|error| format!("invalid upstream response: {error}"))?;
    if let Some(error) = value.get("error") {
        let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("request failed");
        return Err(format!("{message} ({code})"));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}
