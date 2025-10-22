use crate::errors::Result;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub struct SigSet {
    pub(crate) rules: Arc<yara_x::Rules>,
    signatures: Vec<Signature>,
}

impl Clone for SigSet {
    fn clone(&self) -> Self {
        Self {
            rules: Arc::clone(&self.rules),
            signatures: self.signatures.clone(),
        }
    }
}

impl SigSet {
    /// Create a new empty SigSet
    pub fn new() -> Self {
        Self {
            rules: Arc::new(yara_x::Compiler::new().build()),
            signatures: Vec::new(),
        }
    }

    /// Create a SigSet from a single signature
    pub fn from_signature(signature: Signature) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(signature.0.as_str())?;
        let rules = compiler.build();
        Ok(Self {
            rules: Arc::new(rules),
            signatures: vec![signature],
        })
    }

    /// Create a SigSet from multiple signatures
    pub fn from_signatures(signatures: Vec<Signature>) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        for signature in &signatures {
            compiler.add_source(signature.0.as_str())?;
        }
        let rules = compiler.build();
        Ok(Self {
            rules: Arc::new(rules),
            signatures,
        })
    }

    /// Add a single signature to this SigSet, returning a new SigSet
    pub fn with_signature(self, signature: Signature) -> Result<Self> {
        let mut signatures = self.signatures;
        signatures.push(signature);
        Self::from_signatures(signatures)
    }

    /// Add multiple signatures to this SigSet, returning a new SigSet
    pub fn with_signatures(self, new_signatures: Vec<Signature>) -> Result<Self> {
        let mut signatures = self.signatures;
        signatures.extend(new_signatures);
        Self::from_signatures(signatures)
    }

    /// Add all YARA files from a directory (non-recursive)
    pub fn with_sig_dir(self, path: &Path) -> Result<Self> {
        let mut signatures = self.signatures;
        Self::load_signatures_from_dir(path, &mut signatures)?;
        Self::from_signatures(signatures)
    }

    /// Add all YARA files from a directory recursively
    pub fn with_sig_dir_recursive(self, path: &Path) -> Result<Self> {
        let mut signatures = self.signatures;
        Self::load_signatures_from_dir_recursive(path, &mut signatures)?;
        Self::from_signatures(signatures)
    }

    /// Get the number of rules in this signature set
    pub fn count(&self) -> usize {
        self.rules.iter().count()
    }

    // Helper methods

    fn load_signatures_from_dir(path: &Path, signatures: &mut Vec<Signature>) -> Result<()> {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Check for YARA file extensions
            if let Some(extension) = path.extension() {
                let ext = extension.to_string_lossy().to_lowercase();
                if ext == "yar" || ext == "yara" || ext == "yrc" {
                    // Read the file content
                    let content = fs::read_to_string(&path)?;
                    signatures.push(Signature(content));
                }
            }
        }

        Ok(())
    }

    fn load_signatures_from_dir_recursive(
        path: &Path,
        signatures: &mut Vec<Signature>,
    ) -> Result<()> {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively process subdirectories
                Self::load_signatures_from_dir_recursive(&path, signatures)?;
            } else {
                // Check for YARA file extensions
                if let Some(extension) = path.extension() {
                    let ext = extension.to_string_lossy().to_lowercase();
                    if ext == "yar" || ext == "yara" || ext == "yrc" {
                        // Read the file content
                        let content = fs::read_to_string(&path)?;
                        signatures.push(Signature(content));
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for SigSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct Signature(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_signature_valid() {
        let signature_set =
            SigSet::from_signature(Signature("rule test { condition: true }".to_string())).unwrap();

        assert_eq!(1, signature_set.count());
    }

    #[test]
    fn from_signature_invalid() {
        let result = SigSet::from_signature(Signature("rule test { condition: ".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn from_signatures_multiple() {
        let signature_set = SigSet::from_signatures(vec![
            Signature("rule test1 { condition: true }".to_string()),
            Signature("rule test2 { condition: true }".to_string()),
        ])
        .unwrap();

        assert_eq!(2, signature_set.count());
    }

    #[test]
    fn with_signature_chaining() {
        let signature_set = SigSet::new()
            .with_signature(Signature("rule test { condition: true }".to_string()))
            .unwrap();

        assert_eq!(1, signature_set.count());
    }

    #[test]
    fn with_sig_dir_loads_yara_files() {
        use std::path::PathBuf;

        let test_dir = PathBuf::from("tests/test_sigs");
        let result = SigSet::new().with_sig_dir(&test_dir);

        assert!(result.is_ok());
        let sig_set = result.unwrap();
        assert_eq!(sig_set.count(), 1); // We have 1 .yara file in test_sigs
    }

    #[test]
    fn with_sig_dir_nonexistent_directory() {
        use std::path::PathBuf;

        let test_dir = PathBuf::from("tests/nonexistent_dir");
        let result = SigSet::new().with_sig_dir(&test_dir);

        assert!(result.is_err());
    }

    #[test]
    fn test_chaining_with_signature_and_dir() {
        use std::path::PathBuf;

        let test_dir = PathBuf::from("tests/test_sigs");
        let sig_set =
            SigSet::from_signature(Signature("rule test { condition: true }".to_string()))
                .unwrap()
                .with_sig_dir(&test_dir)
                .unwrap();

        // Should have 1 manual + 1 from directory
        assert_eq!(sig_set.count(), 2);
    }
}
