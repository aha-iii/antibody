use serde::{Deserialize, Serialize};

/// Detect phase — aligned with ModSecurity/Coraza phase concepts for response-chain extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectPhase {
    /// Pre-access policies: CC / Geo / Bot / Intel, etc.
    PreAccess,
    /// Request headers.
    RequestHeaders,
    /// Request body / URI / Args.
    RequestBody,
    /// File upload.
    RequestUpload,
    /// Response headers (reserved).
    ResponseHeaders,
    /// Response body (reserved).
    ResponseBody,
    /// Lua / custom scripts.
    Script,
    /// Audit log.
    Logging,
}

impl InspectPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreAccess => "pre_access",
            Self::RequestHeaders => "request_headers",
            Self::RequestBody => "request_body",
            Self::RequestUpload => "request_upload",
            Self::ResponseHeaders => "response_headers",
            Self::ResponseBody => "response_body",
            Self::Script => "script",
            Self::Logging => "logging",
        }
    }
}
