use open_detect::{ScanResult, Scanner, SigSetBuilder, Signature};
use std::fs;

#[test]
fn test_scan_file_with_matching_signature() {
    // Load the OpenDetect test YARA rule
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Test file that contains the signature
    let test_file_path = "tests/test_files/simple_text_with_sig.txt";
    let file_content = fs::read(test_file_path).expect("Failed to read test file");

    let result = scanner.scan_buf(&file_content).expect("Scan failed");

    // Should detect the signature
    match result {
        ScanResult::Malicious(detections) => {
            assert_eq!(detections.len(), 1);
            assert_eq!(detections[0].name, "OpenDetectTest");
        }
        ScanResult::Clean => {
            panic!("Expected malicious result, got clean");
        }
    }
}

#[test]
fn test_scan_file_without_matching_signature() {
    // Load the OpenDetect test YARA rule
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Test file that does NOT contain the signature
    let test_file_path = "tests/test_files/simple_text_without_sig.txt";
    let file_content = fs::read(test_file_path).expect("Failed to read test file");

    let result = scanner.scan_buf(&file_content).expect("Scan failed");

    // Should be clean
    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_scan_empty_file() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Scan empty content
    let result = scanner.scan_buf(&[]).expect("Scan failed");

    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_scan_signature_at_different_positions() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Test signature at the beginning
    let content_start = b"b3BlbmRldGVjdAo= followed by text";
    let result = scanner.scan_buf(content_start).expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));

    // Test signature at the end
    let content_end = b"some text followed by b3BlbmRldGVjdAo=";
    let result = scanner.scan_buf(content_end).expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));

    // Test signature in the middle
    let content_middle = b"text before b3BlbmRldGVjdAo= text after";
    let result = scanner.scan_buf(content_middle).expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_multiple_scans_with_same_scanner() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // First scan - malicious
    let result1 = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");
    assert!(matches!(result1, ScanResult::Malicious(_)));

    // Second scan - clean
    let result2 = scanner.scan_buf(b"clean content").expect("Scan failed");
    assert_eq!(result2, ScanResult::Clean);

    // Third scan - malicious again
    let result3 = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");
    assert!(matches!(result3, ScanResult::Malicious(_)));
}

#[test]
fn test_scan_result_detection_details() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    let result = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");

    match result {
        ScanResult::Malicious(detections) => {
            assert_eq!(detections.len(), 1);
            let detection = &detections[0];
            assert_eq!(detection.name, "OpenDetectTest");
        }
        ScanResult::Clean => {
            panic!("Expected malicious result");
        }
    }
}

#[test]
fn test_signature_set_with_no_rules() {
    // Build an empty signature set
    let result = SigSetBuilder::new().build();

    // Should succeed even with no rules
    assert!(result.is_ok());

    let sig_set = result.unwrap();
    assert_eq!(sig_set.count(), 0);

    let mut scanner = Scanner::from(&sig_set);
    let scan_result = scanner.scan_buf(b"any content").expect("Scan failed");

    // Should always be clean with no rules
    assert_eq!(scan_result, ScanResult::Clean);
}

#[test]
fn test_case_sensitivity_of_signature() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Exact match - should detect
    let result1 = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");
    assert!(matches!(result1, ScanResult::Malicious(_)));

    // Different case - should NOT detect (base64 is case-sensitive)
    let result2 = scanner.scan_buf(b"B3BLBMRLDGVJDAO=").expect("Scan failed");
    assert_eq!(result2, ScanResult::Clean);
}

#[test]
fn test_partial_signature_match() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Partial match should NOT trigger
    let result = scanner.scan_buf(b"b3BlbmRl").expect("Scan failed");
    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_scan_binary_data() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Binary data with signature embedded
    let binary_data = [
        0x00, 0x01, 0x02, 0x03, b'b', b'3', b'B', b'l', b'b', b'm', b'R', b'l', b'd', b'G', b'V',
        b'j', b'd', b'A', b'o', b'=', 0xFF, 0xFE, 0xFD,
    ];

    let result = scanner.scan_buf(&binary_data).expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_scan_large_file_with_signature() {
    let rule_path = "tests/test_sigs/opendetect.yara";
    let rule_content = fs::read_to_string(rule_path).expect("Failed to read YARA rule file");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature(rule_content))
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Create a large file with signature buried in the middle
    let mut large_content = vec![b'A'; 100_000];
    let signature = b"b3BlbmRldGVjdAo=";
    large_content.splice(50_000..50_000, signature.iter().copied());

    let result = scanner.scan_buf(&large_content).expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_scan_result_equality() {
    // Test ScanResult equality
    assert_eq!(ScanResult::Clean, ScanResult::Clean);

    let result1: ScanResult = "test".into();
    let result2: ScanResult = "test".into();
    assert_eq!(result1, result2);

    let result3: ScanResult = "different".into();
    assert_ne!(result1, result3);
}

#[test]
fn test_add_sig_dir_loads_signatures() {
    use std::path::Path;

    let sig_dir = Path::new("tests/test_sigs");

    let sig_set = SigSetBuilder::new()
        .add_sig_dir(sig_dir)
        .expect("Failed to load signatures from directory")
        .build()
        .expect("Failed to build signature set");

    // Should have loaded the opendetect.yara file
    assert_eq!(sig_set.count(), 1);

    // Test that the loaded signature works
    let mut scanner = Scanner::from(&sig_set);
    let result = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));
}

#[test]
fn test_add_sig_dir_with_scan() {
    use std::path::Path;

    let sig_dir = Path::new("tests/test_sigs");

    let sig_set = SigSetBuilder::new()
        .add_sig_dir(sig_dir)
        .expect("Failed to load signatures from directory")
        .build()
        .expect("Failed to build signature set");

    let mut scanner = Scanner::from(&sig_set);

    // Test file with signature
    let file_content =
        fs::read("tests/test_files/simple_text_with_sig.txt").expect("Failed to read test file");
    let result = scanner.scan_buf(&file_content).expect("Scan failed");

    match result {
        ScanResult::Malicious(detections) => {
            assert_eq!(detections.len(), 1);
            assert_eq!(detections[0].name, "OpenDetectTest");
        }
        ScanResult::Clean => panic!("Expected malicious result"),
    }

    // Test file without signature
    let clean_content =
        fs::read("tests/test_files/simple_text_without_sig.txt").expect("Failed to read test file");
    let result = scanner.scan_buf(&clean_content).expect("Scan failed");
    assert_eq!(result, ScanResult::Clean);
}

#[test]
fn test_add_sig_dir_recursive_loads_nested_signatures() {
    use std::path::Path;

    let sig_dir = Path::new("tests/test_sigs");

    let sig_set = SigSetBuilder::new()
        .add_sig_dir_recursive(sig_dir)
        .expect("Failed to load signatures recursively")
        .build()
        .expect("Failed to build signature set");

    // Should have loaded both opendetect.yara and subdir/nested_rule.yara
    assert_eq!(sig_set.count(), 2);

    let mut scanner = Scanner::from(&sig_set);

    // Test with the main signature
    let result = scanner.scan_buf(b"b3BlbmRldGVjdAo=").expect("Scan failed");
    assert!(matches!(result, ScanResult::Malicious(_)));

    // Test with the nested signature
    let result = scanner
        .scan_buf(b"NESTED_TEST_SIGNATURE")
        .expect("Scan failed");
    match result {
        ScanResult::Malicious(detections) => {
            assert_eq!(detections.len(), 1);
            assert_eq!(detections[0].name, "NestedTestRule");
        }
        ScanResult::Clean => panic!("Expected malicious result"),
    }
}

#[test]
fn test_add_sig_dir_nonexistent_directory() {
    use std::path::Path;

    let sig_dir = Path::new("tests/nonexistent_directory");

    let result = SigSetBuilder::new().add_sig_dir(sig_dir);

    assert!(result.is_err());
}

#[test]
fn test_add_sig_dir_ignores_non_yara_files() {
    use std::path::Path;

    // This directory contains both .yara and .txt files
    let sig_dir = Path::new("tests/test_sigs");

    let sig_set = SigSetBuilder::new()
        .add_sig_dir(sig_dir)
        .expect("Failed to load signatures")
        .build()
        .expect("Failed to build signature set");

    // Should only load .yara files, not .txt or other files
    assert_eq!(sig_set.count(), 1);
}

#[test]
fn test_combine_manual_and_dir_signatures() {
    use std::path::Path;

    let sig_dir = Path::new("tests/test_sigs");

    let sig_set = SigSetBuilder::new()
        .add_sigs(Signature("rule ManualRule { condition: true }".to_string()))
        .add_sig_dir(sig_dir)
        .expect("Failed to load signatures from directory")
        .build()
        .expect("Failed to build signature set");

    // Should have 1 manual rule + 1 from directory
    assert_eq!(sig_set.count(), 2);

    let mut scanner = Scanner::from(&sig_set);

    // The manual rule should always match
    let result = scanner.scan_buf(b"any content").expect("Scan failed");
    match result {
        ScanResult::Malicious(detections) => {
            assert!(detections.iter().any(|d| d.name == "ManualRule"));
        }
        ScanResult::Clean => panic!("Expected malicious result from ManualRule"),
    }
}
