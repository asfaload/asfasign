use clap::Parser;
use std::net::SocketAddr;
use tower_http::services::ServeDir;

#[derive(Parser)]
struct Args {
    /// Directory to serve
    #[arg(long)]
    dir: String,

    /// Port to listen on (0 for random)
    #[arg(long, default_value = "0")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let app = axum::Router::new().fallback_service(ServeDir::new(&args.dir));

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    println!("LISTENING_PORT={}", local_addr.port());

    axum::serve(listener, app).await.unwrap();
}
