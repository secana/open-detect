use crate::{errors::Result, scan_result::ScanResult, signature::SigSet};
use archive::{ArchiveExtractor, ArchiveFormat};
use mime_type::{MimeFormat, MimeType};
use std::path::Path;

pub struct Scanner<'a> {
    scanner: yara_x::Scanner<'a>,
}

impl Scanner<'_> {
    pub fn scan_buf(&mut self, buf: &[u8]) -> Result<ScanResult> {
        if let Some(file_type) = Self::infer_file_type(buf)
            && ArchiveFormat::is_supported_mime(&file_type)
        {
            return self.scan_buf_ft(buf, &file_type);
        }
        let sr = self.scanner.scan(buf)?.into();
        Ok(sr)
    }

    pub fn scan_file(&mut self, path: &Path) -> Result<ScanResult> {
        let buf = std::fs::read(path)?;
        self.scan_buf(&buf)
    }

    pub fn scan_buf_ft(&mut self, buf: &[u8], file_type: &MimeType) -> Result<ScanResult> {
        if ArchiveFormat::is_supported_mime(file_type) {
            self.scan_archive_buf(buf, file_type)
        } else {
            let sr = self.scanner.scan(buf)?.into();
            Ok(sr)
        }
    }

    pub fn scan_file_ft(&mut self, path: &Path, file_type: &MimeType) -> Result<ScanResult> {
        let buf = std::fs::read(path)?;
        self.scan_buf_ft(&buf, file_type)
    }

    fn scan_archive_buf(&mut self, buf: &[u8], file_type: &MimeType) -> Result<ScanResult> {
        let format = match ArchiveFormat::try_from(file_type) {
            Ok(fmt) => fmt,
            Err(_) => {
                // If we can't handle it as an archive, scan directly
                let sr = self.scanner.scan(buf)?.into();
                return Ok(sr);
            }
        };

        self.scan_archive(buf, format)
    }

    /// Scan an archive using the unified archive crate
    fn scan_archive(&mut self, buf: &[u8], format: ArchiveFormat) -> Result<ScanResult> {
        // Create extractor with reasonable limits
        let extractor = ArchiveExtractor::new()
            .with_max_file_size(500 * 1024 * 1024) // 500 MB per file
            .with_max_total_size(2 * 1024 * 1024 * 1024); // 2 GB total

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

impl<'a> From<&'a SigSet> for Scanner<'a> {
    fn from(signature_set: &'a SigSet) -> Self {
        Scanner {
            scanner: yara_x::Scanner::new(&signature_set.rules),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{SigSetBuilder, Signature};

    #[test]
    fn scan_one_sig_matches() {
        let signature_set = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: true }".to_string()))
            .build()
            .unwrap();
        let mut scanner = Scanner::from(&signature_set);

        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::from("test"), result);
    }

    #[test]
    fn scan_one_sig_no_match() {
        let signature_set = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: false }".to_string()))
            .build()
            .unwrap();
        let mut scanner = Scanner::from(&signature_set);
        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::Clean, result);
    }

    #[test]
    fn scan_multiple_sigs_match() {
        let signature_set = SigSetBuilder::new()
            .add_sig(vec![
                Signature("rule test1 { condition: true }".to_string()),
                Signature("rule test2 { condition: true }".to_string()),
            ])
            .build()
            .unwrap();
        let mut scanner = Scanner::from(&signature_set);
        let result = scanner.scan_buf(b"test input").unwrap();
        assert_eq!(ScanResult::from(vec!["test1", "test2"]), result);
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
}
