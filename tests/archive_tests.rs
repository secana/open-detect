use mime_type::MimeType;
use open_detect::{ScanResult, Scanner, SigSet};
use std::fs;
use std::path::Path;

/// Helper function to load the test signature set
fn load_test_sigset() -> open_detect::SigSet {
    let sig_dir = Path::new("tests/test_sigs");
    SigSet::new()
        .with_sig_dir_recursive(sig_dir)
        .expect("Failed to load test signatures")
}

/// Helper function to scan an archive file
fn scan_archive(archive_path: &Path) -> ScanResult {
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let archive_data = fs::read(archive_path).expect("Failed to read archive file");
    scanner.scan_buf(&archive_data).expect("Scan failed")
}

#[test]
fn test_scan_mixed_content_zip() {
    let archive_path = Path::new("tests/test_archives/mixed_content.zip");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            // Should detect the test signatures in the malicious files
            assert!(
                !detections.is_empty(),
                "Expected detections in mixed content"
            );
            // We expect multiple detections from the 3 malicious files
            assert!(detections.len() >= 3, "Expected at least 3 detections");
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in mixed content archive");
        }
    }
}

#[test]
fn test_scan_mixed_content_tar() {
    let archive_path = Path::new("tests/test_archives/mixed_content.tar");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            assert!(
                !detections.is_empty(),
                "Expected detections in mixed content"
            );
            assert!(detections.len() >= 3, "Expected at least 3 detections");
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in mixed content archive");
        }
    }
}

#[test]
fn test_scan_mixed_content_tar_gz() {
    let archive_path = Path::new("tests/test_archives/mixed_content.tar.gz");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            assert!(
                !detections.is_empty(),
                "Expected detections in mixed content"
            );
            assert!(detections.len() >= 3, "Expected at least 3 detections");
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in mixed content archive");
        }
    }
}

#[test]
fn test_scan_mixed_content_tar_bz2() {
    let archive_path = Path::new("tests/test_archives/mixed_content.tar.bz2");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            assert!(
                !detections.is_empty(),
                "Expected detections in mixed content"
            );
            assert!(detections.len() >= 3, "Expected at least 3 detections");
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in mixed content archive");
        }
    }
}

#[test]
fn test_scan_clean_only_zip() {
    let archive_path = Path::new("tests/test_archives/clean_only.zip");
    let result = scan_archive(archive_path);

    assert_eq!(
        result,
        ScanResult::Clean,
        "Clean archive should not have any detections"
    );
}

#[test]
fn test_scan_clean_only_tar_gz() {
    let archive_path = Path::new("tests/test_archives/clean_only.tar.gz");
    let result = scan_archive(archive_path);

    assert_eq!(
        result,
        ScanResult::Clean,
        "Clean archive should not have any detections"
    );
}

#[test]
fn test_scan_malicious_only_zip() {
    let archive_path = Path::new("tests/test_archives/malicious_only.zip");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            // All 5 files contain signatures, so we should have at least 5 detections
            assert!(
                detections.len() >= 5,
                "Expected at least 5 detections, got {}",
                detections.len()
            );

            // Verify all detections have rule names
            for detection in &detections {
                assert!(
                    !detection.name.is_empty(),
                    "Detection should have a rule name"
                );
            }
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in malicious_only archive");
        }
    }
}

#[test]
fn test_scan_malicious_only_tar_gz() {
    let archive_path = Path::new("tests/test_archives/malicious_only.tar.gz");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            assert!(detections.len() >= 5, "Expected at least 5 detections");
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in malicious_only archive");
        }
    }
}

#[test]
fn test_scan_nested_archive_zip() {
    // This test verifies that nested archives are handled (recursive scanning)
    let archive_path = Path::new("tests/test_archives/nested_archive.zip");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            // The nested archive contains malicious files, so we should detect them
            assert!(
                !detections.is_empty(),
                "Expected detections in nested archive"
            );
            // Should detect all 5 files from the inner malicious_only.zip
            assert!(
                detections.len() >= 5,
                "Expected at least 5 detections from nested archive"
            );
        }
        ScanResult::Clean => {
            panic!(
                "Expected malicious results in nested archive (contains malicious inner archive)"
            );
        }
    }
}

#[test]
fn test_scan_nested_archive_tar_gz() {
    let archive_path = Path::new("tests/test_archives/nested_archive.tar.gz");
    let result = scan_archive(archive_path);

    match result {
        ScanResult::Malicious(detections) => {
            assert!(
                !detections.is_empty(),
                "Expected detections in nested archive"
            );
            assert!(
                detections.len() >= 5,
                "Expected at least 5 detections from nested archive"
            );
        }
        ScanResult::Clean => {
            panic!("Expected malicious results in nested archive");
        }
    }
}

#[test]
fn test_format_consistency_across_compression() {
    // Verify that different compression formats give consistent detection results
    let zip_path = Path::new("tests/test_archives/mixed_content.zip");
    let tar_path = Path::new("tests/test_archives/mixed_content.tar");
    let tar_gz_path = Path::new("tests/test_archives/mixed_content.tar.gz");
    let tar_bz2_path = Path::new("tests/test_archives/mixed_content.tar.bz2");

    let zip_result = scan_archive(zip_path);
    let tar_result = scan_archive(tar_path);
    let tar_gz_result = scan_archive(tar_gz_path);
    let tar_bz2_result = scan_archive(tar_bz2_path);

    // All should detect malicious content
    assert!(matches!(zip_result, ScanResult::Malicious(_)));
    assert!(matches!(tar_result, ScanResult::Malicious(_)));
    assert!(matches!(tar_gz_result, ScanResult::Malicious(_)));
    assert!(matches!(tar_bz2_result, ScanResult::Malicious(_)));

    // All should have similar number of detections (at least 3)
    if let ScanResult::Malicious(detections) = zip_result {
        assert!(detections.len() >= 3);
    }
    if let ScanResult::Malicious(detections) = tar_result {
        assert!(detections.len() >= 3);
    }
    if let ScanResult::Malicious(detections) = tar_gz_result {
        assert!(detections.len() >= 3);
    }
    if let ScanResult::Malicious(detections) = tar_bz2_result {
        assert!(detections.len() >= 3);
    }
}

#[test]
fn test_scan_file_method() {
    // Test the scan_file method instead of scan_buf
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let archive_path = Path::new("tests/test_archives/clean_only.zip");
    let result = scanner.scan_file(archive_path).expect("Scan failed");

    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_scan_file_malicious() {
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let archive_path = Path::new("tests/test_archives/malicious_only.zip");
    let result = scanner.scan_file(archive_path).expect("Scan failed");

    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_scan_buf_ft_with_zip() {
    // Test scanning with explicit file type
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let archive_path = Path::new("tests/test_archives/clean_only.zip");
    let archive_data = fs::read(archive_path).expect("Failed to read archive");

    let result = scanner
        .scan_buf_ft(&archive_data, &MimeType::Archive(mime_type::Archive::Zip))
        .expect("Scan failed");

    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_scan_file_ft_with_zip() {
    // Test scanning file with explicit file type
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let archive_path = Path::new("tests/test_archives/malicious_only.zip");
    let result = scanner
        .scan_file_ft(archive_path, &MimeType::Archive(mime_type::Archive::Zip))
        .expect("Scan failed");

    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_scan_non_archive_file() {
    // Test that non-archive files are scanned correctly
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    let file_path = Path::new("tests/test_files/simple_text_with_sig.txt");
    let result = scanner.scan_file(file_path).expect("Scan failed");

    match result {
        ScanResult::Malicious(detections) => {
            assert_eq!(detections.len(), 1);
            assert_eq!(detections[0].name, "OpenDetectTest");
        }
        ScanResult::Clean => {
            panic!("Expected malicious result for file with signature");
        }
    }
}

#[test]
fn test_scan_performance_basic() {
    // Basic performance test - should complete in reasonable time
    use std::time::Instant;

    let archive_path = Path::new("tests/test_archives/mixed_content.zip");

    let start = Instant::now();
    let _result = scan_archive(archive_path);
    let duration = start.elapsed();

    // Should complete in less than 1 second for small test archives
    assert!(
        duration.as_secs() < 1,
        "Archive scanning took too long: {:?}",
        duration
    );
}

#[test]
fn test_multiple_scans_with_same_scanner() {
    // Verify that scanner can be reused for multiple scans
    let sig_set = load_test_sigset();
    let mut scanner = Scanner::from(sig_set);

    // Scan clean archive
    let clean_path = Path::new("tests/test_archives/clean_only.zip");
    let result1 = scanner.scan_file(clean_path).expect("Scan failed");
    assert_eq!(result1, ScanResult::Clean);

    // Scan malicious archive
    let malicious_path = Path::new("tests/test_archives/malicious_only.zip");
    let result2 = scanner.scan_file(malicious_path).expect("Scan failed");
    assert!(matches!(result2, ScanResult::Malicious(_)));

    // Scan clean again
    let result3 = scanner.scan_file(clean_path).expect("Scan failed");
    assert_eq!(result3, ScanResult::Clean);
}
