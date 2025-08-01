// sync 18
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::Response,
    routing::post,
};
use std::io::{Cursor, Read, Write};
use tokio::task;
use zstd::stream::{Encoder as ZstdEncoder, read::Decoder as ZstdDecoder};

const AES_KEY: &[u8; 32] = b"01234567012345670123456701234567";
const AES_NONCE: &[u8; 12] = b"unique nonce";

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/encode", post(encrypt_handler))
        .route("/decode", post(decrypt_handler))
        .layer(DefaultBodyLimit::max(14 * 1024 * 1024));

    let addr = "0.0.0.0:8080";
    println!("Listening on {addr}");
    let listen = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listen, app).await.unwrap();
}

// ENCRYPT: full body → compress → encrypt → [ciphertext + tag]
async fn encrypt_handler(body: Bytes) -> Result<Response<Body>, (StatusCode, String)> {
    let data = body.to_vec();

    // Здесь мы получаем Vec<u8> или String-ошибку
    let buf: Vec<u8> = task::spawn_blocking(move || -> Result<_, String> {
        // 1) Zstd compress
        let mut compressed = Vec::new();
        {
            let mut encoder = ZstdEncoder::new(&mut compressed, 3)
                .map_err(|e| format!("zstd init error: {e}"))?;
            encoder
                .write_all(&data)
                .map_err(|e| format!("zstd write error: {e}"))?;
            encoder
                .finish()
                .map_err(|e| format!("zstd finish error: {e}"))?;
        }

        // 2) AES-GCM encrypt
        let cipher = Aes256Gcm::new(AES_KEY.into());
        let nonce = Nonce::from_slice(AES_NONCE);
        let mut buf = compressed;
        buf.reserve(16);
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buf)
            .map_err(|e| format!("aes-gcm encrypt error: {e}"))?;
        buf.extend_from_slice(&tag);

        Ok(buf)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn error: {e}"),
        )
    })
    .unwrap()
    .unwrap();

    // Собираем HTTP-ответ
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(buf))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(resp)
}

// DECRYPT: full body → split tag → decrypt → decompress → plaintext
async fn decrypt_handler(body: Bytes) -> Result<Response<Body>, (StatusCode, String)> {
    let data = body.to_vec();

    let plain: Vec<u8> = task::spawn_blocking(move || -> Result<_, String> {
        const TAG_LEN: usize = 16;
        if data.len() < TAG_LEN {
            return Err("ciphertext too short".into());
        }

        // Разделяем ciphertext и tag
        let mut ct = data;
        let tag = ct.split_off(ct.len() - TAG_LEN);

        // 1) AES-GCM decrypt
        let cipher = Aes256Gcm::new(AES_KEY.into());
        let nonce = Nonce::from_slice(AES_NONCE);
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut ct, tag.as_slice().into())
            .map_err(|e| format!("aes-gcm decrypt error: {e}"))?;

        // 2) Zstd decompress
        let mut decoder = ZstdDecoder::new(Cursor::new(&ct))
            .map_err(|e| format!("zstd decoder init error: {e}"))?;
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|e| format!("zstd decode error: {e}"))?;

        Ok(out)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn error: {e}"),
        )
    })
    .unwrap()
    .unwrap();

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(plain))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(resp)
}
