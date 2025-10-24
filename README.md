# open-detect

A fast, flexible malware detection engine with YARA rule support and automatic archive extraction for security researchers.

[![Crates.io](https://img.shields.io/crates/v/open-detect.svg)](https://crates.io/crates/open-detect)
[![Documentation](https://docs.rs/open-detect/badge.svg)](https://docs.rs/open-detect)
[![License](https://img.shields.io/crates/l/open-detect.svg)](https://github.com/secana/open-detect)

  Disclaimer: This project is still in early development and should not be used for production purposes.
  The API is subject to change without notice.

## Features

- **YARA-based detection** - Leverage the power of YARA rules for pattern-based malware detection
- **Automatic archive extraction** - Recursively scans ZIP, TAR, GZ, BZ2 archives without manual extraction
- **Thread-safe** - Scanner is both `Send` and `Sync` for concurrent scanning operations

## Quick Start

```rust
use open_detect::{Scanner, SigSet, ScanResult};
use std::path::Path;

// Load YARA signatures from a directory
let sig_set = SigSet::new()
    .with_sig_dir_recursive(Path::new("signatures"))
    .expect("Failed to load signatures");

// Create scanner with default settings
let scanner = Scanner::new(sig_set);

// Scan a file
match scanner.scan_file(Path::new("suspicious.exe")).unwrap() {
    ScanResult::Clean => println!("File is clean"),
    ScanResult::Malicious(detections) => {
        println!("Threats detected:");
        for detection in detections {
            println!("  - {}", detection.name);
        }
    }
}
```

## Usage Examples

### Scan a Buffer

```rust
use open_detect::{Scanner, SigSet, Signature};

let sig = Signature(r#"
    rule ExampleMalware {
        strings:
            $a = "malicious_pattern"
        condition:
            $a
    }
"#.to_string());

let sig_set = SigSet::from_signature(sig).unwrap();
let scanner = Scanner::new(sig_set);

let data = b"some data with malicious_pattern inside";
let result = scanner.scan_buf(data).unwrap();
```

### Configure Extraction Limits

```rust
use open_detect::{Scanner, SigSet};

let sig_set = SigSet::new();
let scanner = Scanner::new(sig_set)
    .with_max_extracted_size(100 * 1024 * 1024)      // 100 MB per file
    .with_max_total_extracted_size(1024 * 1024 * 1024); // 1 GB total
```

### Build Signature Sets

```rust
use open_detect::{SigSet, Signature};
use std::path::Path;

// From individual signatures
let sig_set = SigSet::from_signatures(vec![
    Signature("rule test1 { condition: true }".to_string()),
    Signature("rule test2 { strings: $a = \"test\" condition: $a }".to_string()),
]).unwrap();

// From a directory (loads .yar, .yara, .yrc files)
let sig_set = SigSet::new()
    .with_sig_dir(Path::new("signatures"))
    .unwrap();

// Combine multiple sources
let sig_set = SigSet::from_signature(
    Signature("rule custom { condition: true }".to_string())
)
.unwrap()
.with_sig_dir_recursive(Path::new("signatures"))
.unwrap();
```

## Related Projects

This crate is built on top of excellent open-source projects:

- **[YARA-X](https://github.com/VirusTotal/yara-x)** - Next-generation YARA engine written in Rust by VirusTotal. Provides the core pattern matching capabilities.
- **[YARA](https://github.com/VirusTotal/yara)** - The original pattern matching tool for malware researchers. YARA-X is a modern reimplementation.
- **[archive](https://crates.io/crates/archive)** - Archive extraction library supporting multiple formats.
- **[infer](https://crates.io/crates/infer)** - File type detection from magic numbers.
