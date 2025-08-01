use crypt_compress_axum_server::app::create_app;

#[tokio::main]
async fn main() {
    println!("[main] Starting server");
    
    let app = create_app();

    let addr = "0.0.0.0:8080";
    println!("[main] Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
