use std::collections::HashMap;
use std::fs;

use auth_resolver::{AuthContext, AuthResolver, AuthResolverError};
use base64ct::Encoding as _;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{DecodingKey, Header, Validation};
use log::{debug, info};
use serde::Deserialize;
use warp::http::{HeaderMap, HeaderValue};

#[async_trait::async_trait]
pub trait KeyResolver {
    async fn resolve_key(&self, header: &Header) -> Result<DecodingKey, AuthResolverError>;
}

pub struct KidResolver {
    jwk_store: JwkSet,
}

impl KidResolver {
    pub fn new(key_set_loc: &str) -> Result<Self, AuthResolverError> {
        let r = fs::read_to_string(key_set_loc)
            .map_err(|err| AuthResolverError::new(format!("Could not load jwk set from location: {}; {}", key_set_loc, err)))?;
        let keyfile: JwkSet = serde_json::from_str(&r).map_err(|err| AuthResolverError::new(format!("Could not load parse jwk set: {}", err)))?;

        Ok(Self { jwk_store: keyfile })
    }
}

#[async_trait::async_trait]
impl KeyResolver for KidResolver {
    async fn resolve_key(&self, header: &Header) -> Result<DecodingKey, AuthResolverError> {
        let kid = header.kid.as_ref().ok_or_else(|| AuthResolverError::new("No kid present in header".into()))?;

        // Get the key
        info!("Resolving key for kid: {}", kid);
        debug!("Keys in store: {:?}", self.jwk_store.keys);

        let key: &Jwk = match self.jwk_store.find(&kid) {
            Some(key) => key,
            None => return Err(AuthResolverError::new(format!("Could not find key for kid: {}", kid))),
        };
        // match self.jwk_store.find(&kid) {
        //     Some(key) => DecodingKey::from_jwk(key)
        //         .map_err(|err| AuthResolverError::new(format!("Could not transform jwk ({}) into DecodingKey: {}", kid, err))),
        //     None => Err(AuthResolverError::new(format!("Could not find key for kid: {}", kid))),
        // }

        // Extract the secret from it
        let secret: Vec<u8> = if let AlgorithmParameters::OctetKey(oct) = &key.algorithm {
            match base64ct::Base64Url::decode_vec(&oct.value) {
                Ok(val) => val,
                Err(err) => return Err(AuthResolverError::new(format!("Could not decode secret key as URL-safe base64: {err}"))),
            }
        } else {
            return Err(AuthResolverError::new("Unsupported key type".into()));
        };

        // Now return that as decoding key
        Ok(DecodingKey::from_secret(&secret))
    }
}

pub struct JwtResolver<KR: KeyResolver> {
    config: JwtConfig,
    key_resolver: KR,
}

#[derive(Deserialize)]
pub struct JwtConfig {
    initiator_claim: String,
}

impl<KR> JwtResolver<KR>
where
    KR: KeyResolver + Sync,
{
    pub fn new(config: JwtConfig, key_resolver: KR) -> Result<Self, Box<dyn std::error::Error>> { return Ok(JwtResolver { config, key_resolver }); }

    pub fn extract_jwt(&self, auth_header: Option<&HeaderValue>) -> Result<String, AuthResolverError> {
        let header_val: &str = match auth_header {
            Some(v) => match v.to_str() {
                Ok(v) => v,
                Err(_) => return Err(AuthResolverError::new("Invalid authorization header".into())),
            },
            None => {
                return Err(AuthResolverError::new("Authorization header not present".into()));
            },
        };

        let parts = header_val.splitn(2, " ").collect::<Vec<&str>>();

        if parts[0] != "Bearer" {
            return Err(AuthResolverError::new("Invalid authorization header".into()));
        }

        Ok(parts[1].into())
    }
}

#[async_trait::async_trait]
impl<KR> AuthResolver for JwtResolver<KR>
where
    KR: KeyResolver + Sync + Send,
{
    async fn authenticate(&self, headers: HeaderMap) -> Result<AuthContext, AuthResolverError> {
        info!("Handling JWT authentication for incoming request");

        let raw_jwt = self.extract_jwt(headers.get("Authorization"))?;
        debug!("Received JWT: '{raw_jwt}'");

        let header = jsonwebtoken::decode_header(&raw_jwt).map_err(|err| AuthResolverError::new(format!("Could not parse header: {}", err)))?;
        debug!("JWT header: '{header:?}'");

        debug!("Resolving key in keystore...");
        let decoding_key = self.key_resolver.resolve_key(&header).await?;
        let validation = Validation::new(header.alg);
        debug!("Validating JWT with {:?}...", header.alg);
        let result = jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(&raw_jwt, &decoding_key, &validation)
            .map_err(|err| AuthResolverError::new(format!("Could not validate jwt: {}", err)))?;
        debug!("Validating OK");

        match result.claims.get(&self.config.initiator_claim) {
            Some(initiator) => match initiator {
                serde_json::Value::Number(v) => Ok(AuthContext { initiator: v.to_string(), system: "TODO implement!".into() }),
                serde_json::Value::String(v) => Ok(AuthContext { initiator: v.clone(), system: "TODO implement!".into() }),
                _ => Err(AuthResolverError::new(format!(
                    "Invalid type for initiator claim (only string or number allowed): {}",
                    self.config.initiator_claim
                ))),
            },
            None => Err(AuthResolverError::new(format!("Missing initiator claim: {}", self.config.initiator_claim))),
        }
    }
}


pub struct MockAuthResolver {
    ctx: AuthContext,
}

impl MockAuthResolver {
    pub fn new(initiator: String, system: String) -> Self { Self { ctx: AuthContext { initiator, system } } }
}

#[async_trait::async_trait]
impl AuthResolver for MockAuthResolver {
    async fn authenticate(&self, _: HeaderMap) -> Result<AuthContext, AuthResolverError> { Ok(self.ctx.clone()) }
}
