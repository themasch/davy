use axum::extract::ConnectInfo;
use http::request::Request;
use std::{net::SocketAddr, str::FromStr};
use tracing::info;

mod authentication;
mod config;
mod server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .expect("please specify the path to a config file as the first argument");

    let config = config::load_config(config_path);

    let dir = std::fs::canonicalize("./storage").unwrap();

    let addr: SocketAddr = SocketAddr::from_str("127.0.0.1:4918").unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let server = server::Server::create("/", dir, config);

    info!("starting server!");

    let router = axum::Router::new().fallback(
        move |ConnectInfo(addr): ConnectInfo<SocketAddr>, req: Request<axum::body::Body>| {
            let srv = server.clone();
            async move {
                info!("got a request: {:?}", req);
                srv.req_handler(req, addr).await
            }
        },
    );

    let router = axum::Router::new()
        .nest("/dav", router)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, router).await.unwrap();
}
