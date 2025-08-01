use async_compression::Level;
use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use axum::{body::Body, response::IntoResponse};
use bytes::Bytes;
use futures_util::TryStreamExt;
use std::io;
use tokio::io::{BufReader, empty};
use tokio::io::{duplex, sink};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::util::*;

const DUPLEX_BUFFER_SIZE: usize = 8 * 1024;

pub async fn encrypt_handler(body: Body) -> impl IntoResponse {
    let (duplex_reader, duplex_writer) = duplex(DUPLEX_BUFFER_SIZE);
    let (_, writer_half) = create_encrypted_stream(empty(), duplex_writer);

    tokio::spawn(process_compression_encryption(
        body.into_data_stream(),
        ZstdEncoder::with_quality(writer_half, Level::Fastest),
    ));

    let output_stream = ReaderStream::new(duplex_reader).map_err(io::Error::other);
    streaming_response(output_stream)
}

pub async fn decrypt_handler(body: Body) -> impl IntoResponse {
    let request_reader = StreamReader::new(body.into_data_stream().map_err(io::Error::other));

    let (reader_half, _) = create_encrypted_stream(request_reader, sink());

    let buf_reader = BufReader::new(reader_half);
    let zstd_decoder = ZstdDecoder::new(buf_reader);

    let output_stream = ReaderStream::new(zstd_decoder)
        .map_ok(Bytes::from)
        .map_err(io::Error::other);

    streaming_response(output_stream)
}