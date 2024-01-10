use axum::extract::ConnectInfo;
use clap::Parser;
use http::request::Request;
use std::{net::SocketAddr, path::PathBuf};
use tracing::info;

use crate::config::Configuration;
use crate::server::Server;

#[derive(Debug, Parser)]
pub(crate) struct ServerConfig {
    #[arg(long)]
    listen: SocketAddr,

    #[arg(long)]
    storage: PathBuf,
}

pub(crate) async fn start_server(cfg: Configuration, server_cfg: ServerConfig) {
    let dir = std::fs::canonicalize(&server_cfg.storage).unwrap();
    let listener = tokio::net::TcpListener::bind(&server_cfg.listen)
        .await
        .unwrap();

    let url_prefix = cfg.global.url_prefix.clone();
    let server = Server::create(dir, cfg);

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

    let router = match url_prefix.as_str() {
        "" => router.into_make_service_with_connect_info::<SocketAddr>(),
        _ => {
            let path = if url_prefix.starts_with('/') {
                url_prefix
            } else {
                format!("/{}", url_prefix)
            };

            axum::Router::new()
                .nest(&path, router)
                .into_make_service_with_connect_info::<SocketAddr>()
        }
    };

    axum::serve(listener, router).await.unwrap();
}
