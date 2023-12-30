use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    body::Body,
    response::{IntoResponse, Response},
    routing::any_service,
};
use dav_server::{fakels::FakeLs, localfs::LocalFs, DavConfig, DavHandler, DavMethodSet};
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::request::Request;
use std::{net::SocketAddr, path::Path, str::FromStr, time::Instant};
use tracing::{debug, error, info, instrument, trace};

mod config;

use config::Configuration;

#[derive(Clone)]
struct Server {
    dav_handler: DavHandler,
    url_prefix: String,
    config: Configuration,
}

impl From<config::UserAccess> for DavMethodSet {
    fn from(val: config::UserAccess) -> Self {
        if !val.read {
            return DavMethodSet::none();
        }

        if !val.write {
            return DavMethodSet::WEBDAV_RO;
        }

        DavMethodSet::WEBDAV_RW
    }
}

impl Server {
    fn create<P: Into<String>, S: AsRef<Path>>(prefix: P, dir: S, config: Configuration) -> Self {
        let url_prefix = prefix.into();

        let dav_handler = DavHandler::builder()
            .filesystem(LocalFs::new(dir, true, false, false))
            .locksystem(FakeLs::new())
            .strip_prefix(&url_prefix)
            .autoindex(true)
            .build_handler();

        Self {
            url_prefix,
            dav_handler,
            config,
        }
    }

    #[instrument(skip(self, req))]
    fn authenticate<B>(&self, req: &Request<B>) -> Result<String, ()> {
        let basic_auth_header = req
            .headers()
            .typed_get::<Authorization<Basic>>()
            .ok_or(())?;

        let username = basic_auth_header.username();

        //FIXME: obvious timing attack: non-existing user fails faster than incorrect password
        let Some(user_pw_hash) = self.config.users.get(username) else {
            return Err(());
        };

        let time = Instant::now();
        let auth_success = Self::verify_password(basic_auth_header.password(), user_pw_hash);
        let duration = time.elapsed();

        trace!("verify_password took {}ms", duration.as_millis());

        if auth_success {
            Ok(username.to_string())
        } else {
            Err(())
        }
    }

    #[instrument]
    fn verify_password(given_password: &str, expected_hash: &str) -> bool {
        let hash = match PasswordHash::new(expected_hash) {
            Ok(h) => h,
            Err(err) => {
                error!("failed to read password hash: {}", err);
                return false;
            }
        };

        Argon2::default()
            .verify_password(given_password.as_bytes(), &hash)
            .is_ok()
    }

    async fn req_handler(&self, req: Request<axum::body::Body>) -> impl IntoResponse {
        let uri = req.uri().path();

        let Some(path) = uri.strip_prefix(&self.url_prefix) else {
            info!("uri does not start with prefix, not a dav request?");
            return Response::builder()
                .status(404)
                .body(Body::from("not found".to_string()))
                .unwrap();
        };

        debug!("checking auth...");
        let Ok(username) = self.authenticate(&req) else {
            return Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Basic realm=\"webdav\"")
                .body(Body::from("authenticate".to_string()))
                .unwrap();
        };
        debug!("authenticated as {}!", &username);

        let cfg_builder = DavConfig::new().principal(&username);

        let path = path.trim_start_matches('/');

        let collection = path.split_once('/').map_or(path, |(col, _)| col);

        let Some(cfg) = self.config.collections.get(collection) else {
            info!(
                "found no matching config for root collection {}",
                collection
            );
            return Response::builder()
                .status(404)
                .body(Body::from("not found".to_string()))
                .unwrap();
        };

        // not sure if this is actually a sane way to do authorization, but it might just work...
        let user_access = cfg.get(&username).cloned().unwrap_or_default();
        let cfg_builder = cfg_builder.methods(user_access.into());

        let (res_parts, res_body) = self
            .dav_handler
            .handle_with(cfg_builder, req)
            .await
            .into_parts();

        // we need to(?) repack the returned body into an axum body to please the type checkers
        // this should cause not a lot of copy, since we just add another wrapper around the stream
        let res_body = Body::from_stream(res_body);
        Response::from_parts(res_parts, res_body)
    }
}

#[tokio::main]
async fn main() {
    let config_path = std::env::args()
        .nth(1)
        .expect("please specify the path to a config file as the first argument");

    let config = config::load_config(config_path);

    let dir = std::fs::canonicalize("./storage").unwrap();

    tracing_subscriber::fmt::init();

    let addr: SocketAddr = SocketAddr::from_str("127.0.0.1:4918").unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let server = Server::create("/dav/", dir, config);

    info!("starting server!");
    let router = axum::Router::new().route(
        "/dav/*segments",
        any_service(tower::service_fn(move |req: Request<axum::body::Body>| {
            let srv = server.clone();
            async move {
                info!("got a request: {:?}", req);
                let result = srv.req_handler(req).await;
                Ok(result)
            }
        })),
    );

    axum::serve(listener, router).await.unwrap();
}
