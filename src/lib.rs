//! # open-detect
//!
//! A fast, flexible malware detection engine with YARA rule support and automatic
//! archive extraction for security researchers.
//!
//! ## Features
//!
//! - **YARA-based detection** - Leverage the power of YARA rules for malware detection
//! - **Automatic archive extraction** - Recursively scans ZIP, TAR, GZ, BZ2 archives
//! - **Thread-safe** - Scanner is both `Send` and `Sync` for concurrent scanning
//! - **Zero-copy scanning** - Efficient scanning with minimal memory overhead
//! - **Flexible API** - Builder pattern for easy configuration
//!
//! ## Quick Start
//!
//! ```no_run
//! use open_detect::{Scanner, SigSet, Signature, ScanResult};
//! use std::path::Path;
//!
//! // Load YARA signatures
//! let sig_set = SigSet::new()
//!     .with_sig_dir_recursive(Path::new("signatures"))
//!     .expect("Failed to load signatures");
//!
//! // Create scanner
//! let scanner = Scanner::new(sig_set);
//!
//! // Scan a file
//! match scanner.scan_file(Path::new("suspicious.exe")).unwrap() {
//!     ScanResult::Clean => println!("File is clean"),
//!     ScanResult::Malicious(detections) => {
//!         for detection in detections {
//!             println!("Detected: {}", detection.name);
//!         }
//!     }
//! }
//! ```
//!
//! ## Scanning Buffers
//!
//! ```no_run
//! use open_detect::{Scanner, SigSet, Signature};
//!
//! let sig_set = SigSet::from_signature(
//!     Signature("rule test { strings: $a = \"malware\" condition: $a }".to_string())
//! ).unwrap();
//!
//! let scanner = Scanner::new(sig_set);
//! let data = b"some data containing malware";
//! let result = scanner.scan_buf(data).unwrap();
//! ```
//!
//! ## Building Signature Sets
//!
//! ```no_run
//! use open_detect::{SigSet, Signature};
//! use std::path::Path;
//!
//! // From a single signature
//! let sig_set = SigSet::from_signature(
//!     Signature("rule test { condition: true }".to_string())
//! ).unwrap();
//!
//! // From multiple signatures
//! let sig_set = SigSet::from_signatures(vec![
//!     Signature("rule test1 { condition: true }".to_string()),
//!     Signature("rule test2 { condition: false }".to_string()),
//! ]).unwrap();
//!
//! // From directory (recursive)
//! let sig_set = SigSet::new()
//!     .with_sig_dir_recursive(Path::new("signatures"))
//!     .unwrap();
//!
//! // Chain multiple sources
//! let sig_set = SigSet::from_signature(
//!     Signature("rule custom { condition: true }".to_string())
//! )
//! .unwrap()
//! .with_sig_dir_recursive(Path::new("signatures"))
//! .unwrap();
//! ```
//!
//! ## Configuring Extraction Limits
//!
//! ```no_run
//! use open_detect::{Scanner, SigSet};
//!
//! # let sig_set = SigSet::new();
//! let scanner = Scanner::new(sig_set)
//!     .with_max_extracted_size(100 * 1024 * 1024)      // 100 MB per file
//!     .with_max_total_extracted_size(1024 * 1024 * 1024); // 1 GB total
//! ```

pub mod errors;
pub mod scan_result;
pub mod scanner;
pub mod signature;

// Re-export commonly used types for convenience
pub use errors::{Error, Result};
pub use scan_result::{Detection, ScanResult};
pub use scanner::Scanner;
pub use signature::{SigSet, Signature};
