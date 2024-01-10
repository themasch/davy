use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use dav_server::{fakels::FakeLs, localfs::LocalFs, DavConfig, DavHandler, DavMethodSet};
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::request::Request;
use std::{net::SocketAddr, path::Path};
use tracing::{debug, error, info, instrument, trace};

use crate::authentication::AuthCache;
use crate::config::{Configuration, UserAccess};

impl From<UserAccess> for DavMethodSet {
    fn from(val: UserAccess) -> Self {
        if !val.read {
            return DavMethodSet::none();
        }

        if !val.write {
            return DavMethodSet::WEBDAV_RO;
        }

        DavMethodSet::WEBDAV_RW
    }
}

#[derive(Clone)]
pub(crate) struct Server {
    dav_handler: DavHandler,
    config: Configuration,
    auth_cache: AuthCache,
}

enum AuthParameters {
    BasicAuth(String, String),
}

impl Server {
    pub(crate) fn create<S: AsRef<Path>>(dir: S, config: Configuration) -> Self {
        let dav_handler = DavHandler::builder()
            .filesystem(LocalFs::new(dir, true, false, false))
            .locksystem(FakeLs::new())
            .autoindex(true)
            .build_handler();

        let auth_cache = AuthCache::new();

        auth_cache.start_eviction_process();

        Self {
            dav_handler,
            config,
            auth_cache,
        }
    }

    fn extract_auth_data<B>(req: &Request<B>) -> Result<AuthParameters, ()> {
        let basic_auth_header = req
            .headers()
            .typed_get::<Authorization<Basic>>()
            .ok_or(())?;

        let username = basic_auth_header.username();
        let password = basic_auth_header.password();

        Ok(AuthParameters::BasicAuth(
            username.to_string(),
            password.to_string(),
        ))
    }

    async fn authenticate(&self, param: AuthParameters, addr: SocketAddr) -> Result<String, ()> {
        let AuthParameters::BasicAuth(username, password) = param;

        //FIXME: obvious timing attack: non-existing userfails faster than incorrect password
        let Some(user_pw_hash) = self.config.users.get(&username) else {
            return Err(());
        };

        if self
            .auth_cache
            .contains(user_pw_hash, &password, &addr.ip().to_string())
            .await
        {
            return Ok(username);
        }

        let auth_success = self.verify_password(&password, user_pw_hash);

        if auth_success {
            self.auth_cache
                .insert(user_pw_hash, &password, &addr.ip().to_string())
                .await;
            Ok(username)
        } else {
            Err(())
        }
    }

    #[instrument(skip_all)]
    fn verify_password(&self, given_password: &str, expected_hash: &str) -> bool {
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

    pub(crate) async fn req_handler(
        &self,
        req: Request<axum::body::Body>,
        addr: SocketAddr,
    ) -> impl IntoResponse {
        let path = req.uri().path();

        debug!("checking auth...");
        let Ok(auth_data) = Self::extract_auth_data(&req) else {
            error!("no authentication data provided?");
            return Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Basic realm=\"webdav\"")
                .body(Body::from("authenticate".to_string()))
                .unwrap();
        };

        let Ok(username) = self.authenticate(auth_data, addr).await else {
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

        trace!("response: {}", res_parts.status);

        // we need to(?) repack the returned body into an axum body to please the type checkers
        // this should cause not a lot of copy, since we just add another wrapper around the stream
        let res_body = Body::from_stream(res_body);
        Response::from_parts(res_parts, res_body)
    }
}
