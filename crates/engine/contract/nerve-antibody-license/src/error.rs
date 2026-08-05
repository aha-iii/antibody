use thiserror::Error;

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license config: {0}")]
    Config(String),
    #[error("license network: {0}")]
    Network(String),
    #[error("license rejected: {0}")]
    Rejected(String),
}
