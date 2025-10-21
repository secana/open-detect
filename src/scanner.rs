use crate::{errors::Result, scan_result::ScanResult, signature::SigSet};

pub struct Scanner<'a> {
    scanner: yara_x::Scanner<'a>,
}

impl Scanner<'_> {
    pub fn scan(&mut self, input: &[u8]) -> Result<ScanResult> {
        let sr = self.scanner.scan(input)?.into();
        Ok(sr)
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
    use crate::signature::{SigSetBuilder, Signature};

    use super::*;

    #[test]
    fn scan_one_sig_matches() {
        let signature_set = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: true }".to_string()))
            .build()
            .unwrap();
        let mut scanner = Scanner::from(&signature_set);

        let result = scanner.scan(b"test input").unwrap();
        assert_eq!(ScanResult::from("test"), result);
    }

    #[test]
    fn scan_one_sig_no_match() {
        let signature_set = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: false }".to_string()))
            .build()
            .unwrap();
        let mut scanner = Scanner::from(&signature_set);
        let result = scanner.scan(b"test input").unwrap();
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
        let result = scanner.scan(b"test input").unwrap();
        assert_eq!(ScanResult::from(vec!["test1", "test2"]), result);
    }
}
