use async_compression::tokio::write::ZstdEncoder;
use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream};
use axum::{body::Body, http::StatusCode, response::Response};
use bytes::Bytes;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use futures_util::StreamExt;
use std::io;
use tokio::io::AsyncWriteExt;

const KEY: &[u8; 32] = b"01234567012345670123456701234567";
const NONCE: &[u8; 20] = b"unique_nonce_20_byte";

/// Creates encrypted stream using predefined KEY and NONCE
pub fn create_encrypted_stream<R, W>(
    reader: R,
    writer: W,
) -> (
    ReadHalf<R, DecryptorLE31<XChaCha20Poly1305>>,
    WriteHalf<W, EncryptorLE31<XChaCha20Poly1305>>,
)
where
    R: tokio::io::AsyncRead + Send + 'static,
    W: tokio::io::AsyncWrite + Send + 'static,
{
    encrypted_stream(reader, writer, KEY.into(), NONCE.into())
}

/// Creates streaming response with 200 status and binary content type
pub fn streaming_response(
    stream: impl tokio_stream::Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Processes input stream: compresses with Zstd and encrypts
pub async fn process_compression_encryption(
    mut src_stream: impl StreamExt<Item = Result<Bytes, axum::Error>> + Unpin,
    mut encoder: ZstdEncoder<WriteHalf<tokio::io::DuplexStream, EncryptorLE31<XChaCha20Poly1305>>>,
) {
    while let Some(chunk) = src_stream.next().await {
        match chunk {
            Ok(bytes) => {
                if let Err(e) = encoder.write_all(&bytes).await {
                    eprintln!("Compression/encryption write error: {e}");
                    break;
                }
            }
            Err(e) => {
                eprintln!("Input stream error: {e}");
                break;
            }
        }
    }

    if let Err(e) = encoder.shutdown().await {
        eprintln!("Encoder finalization error: {e}");
    }
}
