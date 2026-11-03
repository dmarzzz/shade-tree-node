//! One newline-terminated JSON line in, one newline-terminated JSON line out
//! (`docs/WIRE-SPEC.md` section 6; `gateway.mjs` `readEnvelope`, `reply`, `versionRepr`).

use std::fmt;
use std::time::Duration;

use serde_json::Value;
use shadenet_proto::EnvelopeVersion;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_ENVELOPE: usize = 64 * 1024;
const READ_CHUNK: usize = 4096;

#[derive(Debug)]
pub(crate) enum FrameError {
    TooLarge,
    Timeout,
    ClosedBeforeEnvelope,
    NotObject,
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("envelope too large"),
            Self::Timeout => f.write_str("envelope timeout"),
            Self::ClosedBeforeEnvelope => f.write_str("closed before envelope"),
            Self::NotObject => f.write_str("envelope is not an object"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
        }
    }
}

impl FrameError {
    /// Bounded metrics and log label, never peer bytes.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::TooLarge => "envelope-too-large",
            Self::Timeout => "envelope-timeout",
            Self::ClosedBeforeEnvelope | Self::NotObject | Self::Io(_) | Self::Json(_) => {
                "bad-envelope"
            }
        }
    }
}

/// Read up to the first newline, within `timeout` when set. The line may be at most 64 KiB.
/// Returns the parsed envelope and any bytes that followed the newline (early client data).
pub(crate) async fn read_envelope<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Option<Duration>,
) -> Result<(Value, Vec<u8>), FrameError> {
    match timeout {
        Some(limit) => tokio::time::timeout(limit, read_line(reader))
            .await
            .map_err(|_| FrameError::Timeout)?,
        None => read_line(reader).await,
    }
}

async fn read_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Value, Vec<u8>), FrameError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut scanned = 0;
    loop {
        if let Some(offset) = buf[scanned..].iter().position(|b| *b == b'\n') {
            let newline = scanned + offset;
            if newline > MAX_ENVELOPE {
                return Err(FrameError::TooLarge);
            }
            let rest = buf.split_off(newline + 1);
            buf.truncate(newline);
            let envelope: Value = serde_json::from_slice(&buf).map_err(FrameError::Json)?;
            if !matches!(envelope, Value::Object(_) | Value::Array(_)) {
                return Err(FrameError::NotObject);
            }
            return Ok((envelope, rest));
        }
        scanned = buf.len();
        if buf.len() > MAX_ENVELOPE {
            return Err(FrameError::TooLarge);
        }
        let mut chunk = [0_u8; READ_CHUNK];
        let n = reader.read(&mut chunk).await.map_err(FrameError::Io)?;
        if n == 0 {
            return Err(FrameError::ClosedBeforeEnvelope);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Classify the `v` field the way the JavaScript gate does, without reading anything else.
pub(crate) fn version(envelope: &Value) -> EnvelopeVersion {
    match envelope.get("v") {
        None | Some(Value::Null) => EnvelopeVersion::Absent,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(int) => EnvelopeVersion::Int(int),
            None => EnvelopeVersion::Garbage(n.to_string()),
        },
        Some(Value::String(s)) => {
            let head: String = s.chars().take(16).collect();
            EnvelopeVersion::Garbage(serde_json::to_string(&head).unwrap_or_default())
        }
        Some(Value::Bool(_)) => EnvelopeVersion::Garbage("boolean".into()),
        Some(Value::Object(_) | Value::Array(_)) => EnvelopeVersion::Garbage("object".into()),
    }
}

/// `{"ok":false,"err":<reason>[,<extras>]}`. Extras are raw JSON text so the key order inside
/// them matches the JavaScript node byte for byte.
pub(crate) fn refusal(reason: &str, extras: &[(&str, String)]) -> String {
    let mut line = format!(
        "{{\"ok\":false,\"err\":{}",
        serde_json::to_string(reason).unwrap_or_default()
    );
    for (key, value) in extras {
        line.push_str(&format!(",\"{key}\":{value}"));
    }
    line.push('}');
    line
}

/// Write one reply line. Returns false when the peer is gone.
pub(crate) async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> bool {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    writer.write_all(&bytes).await.is_ok()
}

/// Write a refusal and close the connection.
pub(crate) async fn refuse<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) {
    if write_line(writer, line).await {
        let _ = writer.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn read(bytes: &[u8]) -> Result<(Value, Vec<u8>), FrameError> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        read_envelope(&mut cursor, None).await
    }

    #[tokio::test]
    async fn a_line_parses_and_keeps_early_bytes() {
        let (env, rest) = read(b"{\"v\":4}\nearly").await.unwrap();
        assert_eq!(env, json!({"v": 4}));
        assert_eq!(rest, b"early");
    }

    #[tokio::test]
    async fn the_line_cap_counts_the_line_not_the_buffer() {
        let exact = format!("{{\"pad\":\"{}\"}}\n", "x".repeat(MAX_ENVELOPE - 10));
        assert_eq!(exact.len() - 1, MAX_ENVELOPE);
        assert!(read(exact.as_bytes()).await.is_ok());
        let over = format!("{{\"pad\":\"{}\"}}\n", "x".repeat(MAX_ENVELOPE - 9));
        assert!(matches!(
            read(over.as_bytes()).await,
            Err(FrameError::TooLarge)
        ));
        let no_newline = "x".repeat(MAX_ENVELOPE + 1);
        assert!(matches!(
            read(no_newline.as_bytes()).await,
            Err(FrameError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn malformed_lines_name_their_failure() {
        assert!(matches!(
            read(b"{\"v\":4}").await,
            Err(FrameError::ClosedBeforeEnvelope)
        ));
        assert!(matches!(
            read(b"not json\n").await,
            Err(FrameError::Json(_))
        ));
        assert!(matches!(read(b"5\n").await, Err(FrameError::NotObject)));
        assert!(matches!(read(b"null\n").await, Err(FrameError::NotObject)));
        assert!(read(b"[]\n").await.is_ok());
    }

    #[tokio::test]
    async fn a_slow_peer_hits_the_deadline() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let outcome = tokio::join!(
            read_envelope(&mut server, Some(Duration::from_millis(50))),
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = client.write_all(b"{}\n").await;
            }
        );
        assert!(matches!(outcome.0, Err(FrameError::Timeout)));
    }

    #[test]
    fn version_repr_matches_the_javascript_gate() {
        assert_eq!(version(&json!({})), EnvelopeVersion::Absent);
        assert_eq!(version(&json!({"v": null})), EnvelopeVersion::Absent);
        assert_eq!(version(&json!({"v": 4})), EnvelopeVersion::Int(4));
        assert_eq!(version(&json!({"v": -1})), EnvelopeVersion::Int(-1));
        assert_eq!(
            version(&json!({"v": 4.5})),
            EnvelopeVersion::Garbage("4.5".into())
        );
        assert_eq!(
            version(&json!({"v": "4"})),
            EnvelopeVersion::Garbage("\"4\"".into())
        );
        assert_eq!(
            version(&json!({"v": "a".repeat(40)})),
            EnvelopeVersion::Garbage(format!("\"{}\"", "a".repeat(16)))
        );
        assert_eq!(
            version(&json!({"v": true})),
            EnvelopeVersion::Garbage("boolean".into())
        );
        assert_eq!(
            version(&json!({"v": {}})),
            EnvelopeVersion::Garbage("object".into())
        );
        assert_eq!(version(&json!([])), EnvelopeVersion::Absent);
    }

    #[test]
    fn refusals_keep_the_wire_key_order() {
        assert_eq!(
            refusal("bad-target", &[]),
            "{\"ok\":false,\"err\":\"bad-target\"}"
        );
        assert_eq!(
            refusal(
                "unsupported-version:3",
                &[("proto", "{\"min\":4,\"max\":4}".to_string())]
            ),
            "{\"ok\":false,\"err\":\"unsupported-version:3\",\"proto\":{\"min\":4,\"max\":4}}"
        );
    }
}
