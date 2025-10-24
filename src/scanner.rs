use crate::{errors::Result, scan_result::ScanResult, signature::SigSet};
use archive::{ArchiveExtractor, ArchiveFormat};
use mime_type::{MimeFormat, MimeType};
use std::path::Path;

pub struct Scanner {
    sig_set: SigSet,
    max_extracted_size: usize,
    max_total_extracted_size: usize,
}

impl Scanner {
    /// Create a new Scanner from a `SigSet` with default size limits.
    ///
    /// # Default Limits
    /// - Max extracted file size: 500 MB
    /// - Max total extracted size: 2 GB
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet, Signature};
    ///
    /// let sig_set = SigSet::from_signature(
    ///     Signature("rule test { condition: true }".to_string())
    /// ).unwrap();
    /// let scanner = Scanner::new(sig_set);
    /// ```
    #[must_use]
    pub fn new(sig_set: SigSet) -> Self {
        Self {
            sig_set,
            max_extracted_size: 500 * 1024 * 1024, // 500 MB
            max_total_extracted_size: 2 * 1024 * 1024 * 1024, // 2 GB
        }
    }

    /// Set the maximum size for individual extracted files (default: 500 MB).
    ///
    /// This limit applies when scanning archives. Files larger than this limit
    /// will be skipped during archive extraction.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet};
    /// # let sig_set = SigSet::new();
    ///
    /// let scanner = Scanner::new(sig_set)
    ///     .with_max_extracted_size(100 * 1024 * 1024); // 100 MB
    /// ```
    #[must_use]
    pub fn with_max_extracted_size(mut self, size: usize) -> Self {
        self.max_extracted_size = size;
        self
    }

    /// Set the maximum total size for all extracted files (default: 2 GB).
    ///
    /// This limit applies when scanning archives. Once the total size of extracted
    /// files exceeds this limit, extraction stops.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet};
    /// # let sig_set = SigSet::new();
    ///
    /// let scanner = Scanner::new(sig_set)
    ///     .with_max_total_extracted_size(1024 * 1024 * 1024); // 1 GB
    /// ```
    #[must_use]
    pub fn with_max_total_extracted_size(mut self, size: usize) -> Self {
        self.max_total_extracted_size = size;
        self
    }

    /// Scan a buffer of data for malicious content.
    ///
    /// Automatically detects and extracts archives (ZIP, TAR, etc.) before scanning.
    /// If the buffer contains an archive, all files within will be scanned recursively.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The YARA scanner fails to scan the data
    /// - Archive extraction fails (corrupted archive, etc.)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet, Signature, ScanResult};
    ///
    /// # let sig_set = SigSet::from_signature(
    /// #     Signature("rule test { condition: true }".to_string())
    /// # ).unwrap();
    /// let scanner = Scanner::new(sig_set);
    /// let data = b"data to scan";
    ///
    /// match scanner.scan_buf(data).unwrap() {
    ///     ScanResult::Clean => println!("No threats detected"),
    ///     ScanResult::Malicious(detections) => {
    ///         println!("Detected {} threats", detections.len());
    ///     }
    /// }
    /// ```
    pub fn scan_buf(&self, buf: &[u8]) -> Result<ScanResult> {
        if let Some(file_type) = Self::infer_file_type(buf) {
            if ArchiveFormat::is_supported_mime(&file_type) {
                return self.scan_buf_ft(buf, &file_type);
            }
        }
        let mut scanner = yara_x::Scanner::new(&self.sig_set.rules);
        let sr = scanner.scan(buf)?.into();
        Ok(sr)
    }

    /// Scan a file for malicious content.
    ///
    /// Reads the entire file into memory and scans it. Automatically detects
    /// and extracts archives before scanning.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The YARA scanner fails to scan the data
    /// - Archive extraction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet};
    /// use std::path::Path;
    ///
    /// # let sig_set = SigSet::new();
    /// let scanner = Scanner::new(sig_set);
    /// let result = scanner.scan_file(Path::new("suspicious.exe")).unwrap();
    /// ```
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let buf = std::fs::read(path)?;
        self.scan_buf(&buf)
    }

    /// Scan a buffer with an explicitly specified file type.
    ///
    /// This is useful when you know the file type and want to skip automatic detection.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The YARA scanner fails to scan the data
    /// - Archive extraction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet};
    /// use mime_type::{MimeType, Archive};
    ///
    /// # let sig_set = SigSet::new();
    /// let scanner = Scanner::new(sig_set);
    /// let data = b"PK\x03\x04..."; // ZIP file data
    /// let result = scanner.scan_buf_ft(
    ///     data,
    ///     &MimeType::Archive(Archive::Zip)
    /// ).unwrap();
    /// ```
    pub fn scan_buf_ft(&self, buf: &[u8], file_type: &MimeType) -> Result<ScanResult> {
        if ArchiveFormat::is_supported_mime(file_type) {
            self.scan_archive_buf(buf, file_type)
        } else {
            let mut scanner = yara_x::Scanner::new(&self.sig_set.rules);
            let sr = scanner.scan(buf)?.into();
            Ok(sr)
        }
    }

    /// Scan a file with an explicitly specified file type.
    ///
    /// This is useful when you know the file type and want to skip automatic detection.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The YARA scanner fails to scan the data
    /// - Archive extraction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use open_detect::{Scanner, SigSet};
    /// use mime_type::{MimeType, Archive};
    /// use std::path::Path;
    ///
    /// # let sig_set = SigSet::new();
    /// let scanner = Scanner::new(sig_set);
    /// let result = scanner.scan_file_ft(
    ///     Path::new("archive.zip"),
    ///     &MimeType::Archive(Archive::Zip)
    /// ).unwrap();
    /// ```
    pub fn scan_file_ft(&self, path: &Path, file_type: &MimeType) -> Result<ScanResult> {
        let buf = std::fs::read(path)?;
        self.scan_buf_ft(&buf, file_type)
    }

    fn scan_archive_buf(&self, buf: &[u8], file_type: &MimeType) -> Result<ScanResult> {
        let format = match ArchiveFormat::try_from(file_type) {
            Ok(fmt) => fmt,
            Err(_) => {
                // If we can't handle it as an archive, scan directly
                let mut scanner = yara_x::Scanner::new(&self.sig_set.rules);
                let sr = scanner.scan(buf)?.into();
                return Ok(sr);
            }
        };

        self.scan_archive(buf, format)
    }

    /// Scan an archive using the unified archive crate
    fn scan_archive(&self, buf: &[u8], format: ArchiveFormat) -> Result<ScanResult> {
        // Create extractor with reasonable limits
        let extractor = ArchiveExtractor::new()
            .with_max_file_size(self.max_extracted_size)
            .with_max_total_size(self.max_total_extracted_size);

        // Extract all files from the archive
        let extracted_files = extractor
            .extract(buf, format)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let mut all_detections = Vec::new();

        // Scan each extracted file
        for file in extracted_files {
            // Skip directories
            if file.is_directory {
                continue;
            }

            // Recursively scan the contents (might be nested archives)
            let result = self.scan_buf(&file.data)?;

            if let ScanResult::Malicious(detections) = result {
                all_detections.extend(detections);
            }
        }

        if all_detections.is_empty() {
            Ok(ScanResult::Clean)
        } else {
            Ok(ScanResult::Malicious(all_detections))
        }
    }

    /// Infer file type from buffer using the infer crate
    fn infer_file_type(buf: &[u8]) -> Option<MimeType> {
        infer::get(buf)
            .map(|kind| kind.mime_type().to_string())
            .and_then(|mime| MimeType::from_mime(&mime))
    }
}

impl From<SigSet> for Scanner {
    fn from(sig_set: SigSet) -> Self {
        Scanner::new(sig_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Signature;

    #[test]
    fn scan_one_sig_matches() {
        let signature_set =
            SigSet::from_signature(Signature("rule test { condition: true }".to_string())).unwrap();
        let scanner = Scanner::from(signature_set);

        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::from("test"), result);
    }

    #[test]
    fn scan_one_sig_no_match() {
        let signature_set =
            SigSet::from_signature(Signature("rule test { condition: false }".to_string()))
                .unwrap();
        let scanner = Scanner::from(signature_set);
        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::Clean, result);
    }

    #[test]
    fn scan_multiple_sigs_match() {
        let signature_set = SigSet::from_signatures(vec![
            Signature("rule test1 { condition: true }".to_string()),
            Signature("rule test2 { condition: true }".to_string()),
        ])
        .unwrap();
        let scanner = Scanner::from(signature_set);
        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::from(vec!["test1", "test2"]), result);
    }

    #[test]
    fn test_scanner_new() {
        let signature_set =
            SigSet::from_signature(Signature("rule test { condition: true }".to_string())).unwrap();

        let scanner = Scanner::new(signature_set);
        assert_eq!(scanner.max_extracted_size, 500 * 1024 * 1024);
        assert_eq!(scanner.max_total_extracted_size, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_scanner_with_custom_sizes() {
        let signature_set =
            SigSet::from_signature(Signature("rule test { condition: true }".to_string())).unwrap();

        let scanner = Scanner::new(signature_set)
            .with_max_extracted_size(100 * 1024 * 1024) // 100 MB
            .with_max_total_extracted_size(1024 * 1024 * 1024); // 1 GB

        assert_eq!(scanner.max_extracted_size, 100 * 1024 * 1024);
        assert_eq!(scanner.max_total_extracted_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_infer_file_type() {
        // Test ZIP detection
        let zip_magic = b"PK\x03\x04";
        assert_eq!(
            Scanner::infer_file_type(zip_magic),
            Some(MimeType::Archive(mime_type::Archive::Zip))
        );

        let text = b"hello world";
        let result = Scanner::infer_file_type(text);
        assert!(result.is_none());
    }

    #[test]
    fn test_scanner_is_send_and_sync() {
        // Compile-time check that Scanner implements Send and Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<Scanner>();
        assert_sync::<Scanner>();
    }
}
