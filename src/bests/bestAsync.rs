use async_compression::Level;
use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream};
use axum::{
    Router,
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::Bytes;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use futures_util::{StreamExt, TryStreamExt};
use std::io;
use tokio::io::duplex;
use tokio::io::{AsyncWriteExt, BufReader, empty};
use tokio_util::io::{ReaderStream, StreamReader};

const KEY: &[u8; 32] = b"01234567012345670123456701234567";
const NONCE: &[u8; 20] = b"unique_nonce_20_byte";

async fn encrypt_handler(body: Body) -> impl IntoResponse {
    // поток байт из запроса
    let mut src = body.into_data_stream();

    // in‑memory канал
    let (duplex_reader, duplex_writer) = duplex(8 * 1024);

    // получаем только WriteHalf — для шифрования
    let (_unused_read, writer_half): (
        ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
        WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
    ) = encrypted_stream(
        // ReadHalf нам не нужен — «сливаем» его
        empty(),
        duplex_writer,
        KEY.into(),
        NONCE.into(),
    );

    // фоновая задача: читаем запрос → Zstd → AEAD → duplex_writer
    tokio::spawn(async move {
        let mut encoder = ZstdEncoder::with_quality(writer_half, Level::Fastest);
        while let Some(frame) = src.next().await {
            match frame {
                Ok(bytes) => {
                    if let Err(e) = encoder.write_all(&bytes).await {
                        eprintln!("compress+encrypt error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("request error: {e}");
                    break;
                }
            }
        }
        let _ = encoder.shutdown().await;
    });

    // отдаём клиенту ciphertext из duplex_reader
    let stream = ReaderStream::new(duplex_reader);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn decrypt_handler(body: Body) -> impl IntoResponse {
    // HTTP Body -> StreamReader -> AEAD decryptor -> Zstd decoder -> Response
    let request_reader = StreamReader::new(body.into_data_stream().map_err(io::Error::other));

    let (reader_half, _unused): (
        ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
        WriteHalf<_, _>,
    ) = encrypted_stream(
        request_reader,
        empty(), // отбрасываем шифратор
        KEY.into(),
        NONCE.into(),
    );

    let buf_reader = BufReader::new(reader_half);
    let zstd_decoder = ZstdDecoder::new(buf_reader);
    let resp_stream = ReaderStream::new(zstd_decoder)
        .map_ok(Bytes::from)
        .map_err(io::Error::other);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(Body::from_stream(resp_stream))
        .unwrap()
}

#[tokio::main]
async fn main() {
    println!("[main] Starting server");
    let app = Router::new()
        .route("/encode", post(encrypt_handler))
        .route("/decode", post(decrypt_handler));
    let addr = "0.0.0.0:8080";
    println!("[main] Listening on {addr}");
    let listen = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listen, app).await.unwrap();
}
