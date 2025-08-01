use axum::{Router, routing::post};
use crate::handlers::*;

pub fn create_app() -> Router{
    Router::new()
        .route("/encode", post(encrypt_handler))
        .route("/decode", post(decrypt_handler))
}