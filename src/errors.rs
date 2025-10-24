//! Error types for the open-detect crate.

use thiserror::Error;

/// A specialized `Result` type for open-detect operations.
///
/// This type is used throughout the crate for any operation that may produce an error.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during malware detection operations.
///
/// This enum wraps all possible error types that can be returned by the crate.
///
/// # Examples
///
/// ```
/// use open_detect::{SigSet, Signature, Error};
///
/// let result = SigSet::from_signature(
///     Signature("invalid yara rule".to_string())
/// );
/// assert!(result.is_err());
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// Error during YARA signature compilation.
    ///
    /// This occurs when a YARA rule has syntax errors or is otherwise invalid.
    #[error("Signature compilation error: {0}")]
    SignatureError(#[from] yara_x::errors::CompileError),

    /// Error during YARA scanning operation.
    ///
    /// This occurs when the scanning process fails, typically due to resource
    /// constraints or internal YARA errors.
    #[error("Scanning error: {0}")]
    ScanError(#[from] yara_x::errors::ScanError),

    /// I/O error when reading files or directories.
    ///
    /// This occurs when files cannot be read, directories cannot be accessed,
    /// or other filesystem operations fail.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
