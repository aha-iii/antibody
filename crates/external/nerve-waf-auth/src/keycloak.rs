//! Keycloak OIDC JWT validation (JWKS).

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const JWKS_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct KeycloakPublicConfig {
    pub enabled: bool,
    pub auth_server_url: String,
    pub realm: String,
    pub client_id: String,
}

pub struct KeycloakValidator {
    config: KeycloakPublicConfig,
    issuer: String,
    jwks_url: String,
    jwks_cache: RwLock<Option<(Instant, JwkSet)>>,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    /// Deserialization requires the claim; expiry itself is enforced by
    /// `jsonwebtoken::Validation` (validate_exp defaults to true).
    #[allow(dead_code)]
    exp: usize,
    iss: String,
    aud: Option<serde_json::Value>,
    azp: Option<String>,
}

impl KeycloakValidator {
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("KEYCLOAK_ENABLED")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let auth_server_url = std::env::var("KEYCLOAK_AUTH_SERVER_URL")
            .ok()
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())?;
        if !enabled {
            return None;
        }
        let realm = std::env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "saascrmplatformdev".into());
        let client_id = std::env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "crm".into());
        let issuer = format!("{auth_server_url}/realms/{realm}");
        let jwks_url = format!("{issuer}/protocol/openid-connect/certs");
        Some(Self {
            config: KeycloakPublicConfig {
                enabled: true,
                auth_server_url,
                realm,
                client_id,
            },
            issuer,
            jwks_url,
            jwks_cache: RwLock::new(None),
            http: reqwest::Client::new(),
        })
    }

    pub fn public_config(&self) -> KeycloakPublicConfig {
        self.config.clone()
    }

    pub async fn validate_token(&self, token: &str) -> bool {
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                debug!("jwt header decode failed: {e}");
                return false;
            }
        };
        let kid = match header.kid {
            Some(k) => k,
            None => {
                debug!("jwt missing kid");
                return false;
            }
        };
        let jwks = match self.load_jwks().await {
            Some(j) => j,
            None => return false,
        };
        let jwk = match jwks.find(&kid) {
            Some(j) => j,
            None => {
                debug!("jwks kid not found: {kid}");
                return false;
            }
        };
        let key = match decoding_key(jwk) {
            Some(k) => k,
            None => return false,
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        let claims = match decode::<JwtClaims>(token, &key, &validation) {
            Ok(c) => c.claims,
            Err(e) => {
                debug!("jwt decode failed: {e}");
                return false;
            }
        };
        if claims.iss != self.issuer {
            debug!("jwt issuer mismatch");
            return false;
        }
        if !audience_ok(&claims, &self.config.client_id) {
            debug!("jwt audience/azp mismatch");
            return false;
        }
        true
    }

    async fn load_jwks(&self) -> Option<JwkSet> {
        {
            let cache = self.jwks_cache.read().unwrap();
            if let Some((at, jwks)) = cache.as_ref() {
                if at.elapsed() < JWKS_TTL {
                    return Some(jwks.clone());
                }
            }
        }
        let resp = match self.http.get(&self.jwks_url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!("keycloak jwks fetch failed: status {}", r.status());
                return self.stale_jwks();
            }
            Err(e) => {
                warn!("keycloak jwks fetch error: {e}");
                return self.stale_jwks();
            }
        };
        let jwks: JwkSet = match resp.json().await {
            Ok(j) => j,
            Err(e) => {
                warn!("keycloak jwks parse error: {e}");
                return self.stale_jwks();
            }
        };
        *self.jwks_cache.write().unwrap() = Some((Instant::now(), jwks.clone()));
        Some(jwks)
    }

    fn stale_jwks(&self) -> Option<JwkSet> {
        self.jwks_cache
            .read()
            .unwrap()
            .as_ref()
            .map(|(_, j)| j.clone())
    }
}

fn decoding_key(jwk: &Jwk) -> Option<DecodingKey> {
    DecodingKey::from_jwk(jwk).ok()
}

fn audience_ok(claims: &JwtClaims, client_id: &str) -> bool {
    if claims.azp.as_deref() == Some(client_id) {
        return true;
    }
    match &claims.aud {
        Some(serde_json::Value::String(s)) => s == client_id || s == "account",
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| {
            v.as_str()
                .map(|s| s == client_id || s == "account")
                .unwrap_or(false)
        }),
        None => false,
        _ => false,
    }
}
