//! Authentication: API key, local users/JWT, and optional Keycloak OIDC.

mod keycloak;
mod local;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use keycloak::{KeycloakPublicConfig, KeycloakValidator};
use local::{LocalAuth, LocalPublicConfig};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub use keycloak::KeycloakPublicConfig as KeycloakConfig;
pub use local::{LoginRequest, LoginResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None,
    ApiKey,
    Jwt,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthConfigResponse {
    pub enabled: bool,
    pub mode: &'static str,
    pub local: LocalPublicConfig,
    pub keycloak: KeycloakPublicConfig,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub api_keys: HashMap<String, String>, // key -> role
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_keys: HashMap::new(),
        }
    }
}

/// `NERVE_AUTH_ENABLED=0|false|off` disables explicitly; unset or other values = enabled.
pub fn auth_enabled_from_env() -> bool {
    match std::env::var("NERVE_AUTH_ENABLED") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off")
        }
        Err(_) => true,
    }
}

fn auth_mode_from_env(
    local: &Option<LocalAuth>,
    keycloak: &Option<Arc<KeycloakValidator>>,
) -> &'static str {
    match std::env::var("NERVE_AUTH_MODE") {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "local" => "local",
            "keycloak" | "oidc" => "keycloak",
            "none" | "off" => "none",
            _ => {
                if local.is_some() {
                    "local"
                } else if keycloak.is_some() {
                    "keycloak"
                } else {
                    "none"
                }
            }
        },
        Err(_) => {
            if local.is_some() {
                "local"
            } else if keycloak.is_some() {
                "keycloak"
            } else if auth_enabled_from_env() {
                "local"
            } else {
                "none"
            }
        }
    }
}

pub struct AuthState {
    config: RwLock<AuthConfig>,
    keycloak: Option<Arc<KeycloakValidator>>,
    local: Option<LocalAuth>,
    mode: &'static str,
}

impl AuthState {
    pub fn new(
        config: AuthConfig,
        keycloak: Option<KeycloakValidator>,
        local: Option<LocalAuth>,
    ) -> Self {
        let keycloak = keycloak.map(Arc::new);
        let mode = auth_mode_from_env(&local, &keycloak);
        Self {
            config: RwLock::new(config),
            keycloak,
            local,
            mode,
        }
    }

    pub fn from_env() -> Self {
        let mut keys = HashMap::new();
        if let Ok(k) = std::env::var("NERVE_API_KEY") {
            if !k.is_empty() {
                keys.insert(k, "admin".into());
            }
        }
        let keycloak = KeycloakValidator::from_env();
        let local = LocalAuth::from_env();
        let enabled = auth_enabled_from_env();
        if enabled && keys.is_empty() && keycloak.is_none() && local.is_none() {
            eprintln!(
                "nerve-waf-auth: NERVE_AUTH_ENABLED (default on) but no API key, Keycloak, or local auth configured"
            );
        }
        Self::new(
            AuthConfig {
                enabled,
                api_keys: keys,
            },
            keycloak,
            local,
        )
    }

    pub fn validate(&self, key: Option<&str>) -> bool {
        let cfg = self.config.read().unwrap();
        if !cfg.enabled {
            return true;
        }
        key.map(|k| cfg.api_keys.contains_key(k)).unwrap_or(false)
    }

    pub async fn validate_jwt(&self, token: &str) -> bool {
        if let Some(local) = &self.local {
            if local.validate_token(token) {
                return true;
            }
        }
        match &self.keycloak {
            Some(kc) => kc.validate_token(token).await,
            None => false,
        }
    }

    pub async fn authenticate(&self, api_key: Option<&str>, bearer: Option<&str>) -> AuthMethod {
        if let Some(k) = api_key {
            if self.validate(Some(k)) {
                return AuthMethod::ApiKey;
            }
        }
        if let Some(token) = bearer {
            if token.contains('.') && self.validate_jwt(token).await {
                return AuthMethod::Jwt;
            }
            if self.validate(Some(token)) {
                return AuthMethod::ApiKey;
            }
        }
        AuthMethod::None
    }

    pub fn is_enabled(&self) -> bool {
        self.config.read().unwrap().enabled
    }

    pub fn local_config(&self) -> LocalPublicConfig {
        self.local
            .as_ref()
            .map(|l| l.public_config())
            .unwrap_or(LocalPublicConfig { enabled: false })
    }

    pub fn auth_mode(&self) -> &'static str {
        self.mode
    }

    pub fn auth_config_response(&self) -> AuthConfigResponse {
        AuthConfigResponse {
            enabled: self.is_enabled(),
            mode: self.mode,
            local: self.local_config(),
            keycloak: self.keycloak_config(),
        }
    }

    pub fn issue_local_token(&self, username: &str, role: &str) -> Result<LoginResponse, String> {
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| "local auth disabled".to_string())?;
        local.issue_token(username, role)
    }

    pub fn jwt_identity(&self, token: &str) -> Option<(String, String)> {
        self.local.as_ref().and_then(|l| l.claims_from_token(token))
    }

    pub fn keycloak_config(&self) -> KeycloakPublicConfig {
        self.keycloak
            .as_ref()
            .map(|k| k.public_config())
            .unwrap_or(KeycloakPublicConfig {
                enabled: false,
                auth_server_url: String::new(),
                realm: String::new(),
                client_id: String::new(),
            })
    }

    pub fn auth_method_label(&self) -> &'static str {
        match (
            &self.keycloak,
            self.config.read().unwrap().api_keys.is_empty(),
            self.local.is_some(),
        ) {
            (Some(_), false, true) => "local+keycloak+x-api-key",
            (Some(_), false, false) => "keycloak+x-api-key",
            (Some(_), true, true) => "local+keycloak",
            (Some(_), true, false) => "keycloak",
            (None, false, true) => "local+x-api-key",
            (None, false, false) => "x-api-key",
            (None, true, true) => "local",
            (None, true, false) => "none",
        }
    }

    /// RBAC role resolution.
    pub fn resolve_role(
        &self,
        method: AuthMethod,
        api_key: Option<&str>,
        bearer: Option<&str>,
    ) -> String {
        match method {
            AuthMethod::Jwt => bearer
                .and_then(|t| self.jwt_identity(t))
                .map(|(_, role)| role)
                .unwrap_or_else(|| "admin".into()),
            AuthMethod::ApiKey => api_key
                .and_then(|k| self.config.read().unwrap().api_keys.get(k).cloned())
                .unwrap_or_else(|| "admin".into()),
            AuthMethod::None => "admin".into(),
        }
    }
}

pub async fn auth_middleware(
    axum::Extension(auth): axum::Extension<std::sync::Arc<AuthState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if !auth.is_enabled() {
        return Ok(next.run(req).await);
    }
    let api_key = req.headers().get("x-api-key").and_then(|v| v.to_str().ok());
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let method = auth.authenticate(api_key, bearer).await;
    if method == AuthMethod::None {
        Err(StatusCode::UNAUTHORIZED)
    } else {
        Ok(next.run(req).await)
    }
}

#[cfg(test)]
mod test;
