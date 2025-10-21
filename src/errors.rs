use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature compilation error: {0}")]
    SignatureError(#[from] yara_x::errors::CompileError),
    #[error("Scanning error: {0}")]
    ScanError(#[from] yara_x::errors::ScanError),
}
