//! NDJSON helpers matching herdr's JSON API envelope.

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// herdr's limit is 1 MiB per request line.
pub const MAX_LINE: usize = 1024 * 1024;

pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Ok(None);
    }
    if read > MAX_LINE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request line exceeds 1 MiB",
        ));
    }
    Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()))
}

pub async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

pub fn id_of(request: &Value) -> Value {
    request.get("id").cloned().unwrap_or(Value::Null)
}

pub fn method_of(request: &Value) -> &str {
    request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub fn params_of(request: &Value) -> Value {
    request
        .get("params")
        .filter(|params| params.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub fn ok(id: &Value, result: Value) -> String {
    json!({ "id": id, "result": result }).to_string()
}

pub fn error(id: &Value, code: &str, message: &str) -> String {
    json!({ "id": id, "error": { "code": code, "message": message } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_object_params_are_replaced_by_an_empty_object() {
        assert_eq!(params_of(&json!({"params": []})), json!({}));
        assert_eq!(params_of(&json!({"params": "x"})), json!({}));
        assert_eq!(params_of(&json!({})), json!({}));
        assert_eq!(
            params_of(&json!({"params": {"pane_id": "w1:p1"}})),
            json!({"pane_id": "w1:p1"})
        );
    }
}
