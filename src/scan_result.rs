type Detections = Vec<Detection>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    Clean,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub name: String,
}

impl From<&str> for Detection {
    fn from(name: &str) -> Self {
        Detection {
            name: name.to_string(),
        }
    }
}
