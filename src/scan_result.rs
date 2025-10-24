type Detections = Vec<Detection>;

/// Result of a malware scan operation.
///
/// Represents whether the scanned content is clean or contains detected threats.
///
/// # Examples
///
/// ```
/// use open_detect::ScanResult;
///
/// let clean = ScanResult::Clean;
/// assert_eq!(clean, ScanResult::Clean);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    /// No threats detected - the content is clean.
    Clean,
    /// One or more threats detected, with details about each detection.
    Malicious(Detections),
}

impl From<yara_x::ScanResults<'_, '_>> for ScanResult {
    fn from(results: yara_x::ScanResults) -> Self {
        if results.matching_rules().len() == 0 {
            ScanResult::Clean
        } else {
            let detections = results
                .matching_rules()
                .map(|rule| rule.identifier().into())
                .collect();

            ScanResult::Malicious(detections)
        }
    }
}

impl From<String> for ScanResult {
    fn from(name: String) -> Self {
        ScanResult::Malicious(vec![Detection { name }])
    }
}

impl From<&str> for ScanResult {
    fn from(name: &str) -> Self {
        ScanResult::Malicious(vec![Detection {
            name: name.to_string(),
        }])
    }
}

impl From<Vec<&str>> for ScanResult {
    fn from(names: Vec<&str>) -> Self {
        let detections = names
            .into_iter()
            .map(|name| Detection { name: name.into() })
            .collect();
        ScanResult::Malicious(detections)
    }
}

/// Details about a detected threat.
///
/// Contains information about a YARA rule that matched during scanning.
///
/// # Examples
///
/// ```
/// use open_detect::Detection;
///
/// let detection = Detection {
///     name: "MalwareRule".to_string(),
/// };
/// assert_eq!(detection.name, "MalwareRule");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The name/identifier of the YARA rule that matched.
    pub name: String,
}

impl From<&str> for Detection {
    fn from(name: &str) -> Self {
        Detection {
            name: name.to_string(),
        }
    }
}
