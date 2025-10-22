pub mod errors;
pub mod scan_result;
pub mod scanner;
pub mod signature;

// Re-export commonly used types for convenience
pub use errors::{Error, Result};
pub use scan_result::{Detection, ScanResult};
pub use scanner::Scanner;
pub use signature::{SigSet, Signature};
