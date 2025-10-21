use crate::errors::Result;

pub struct SigSet {
    pub(crate) rules: yara_x::Rules,
}

impl SigSet {
    pub fn count(&self) -> usize {
        self.rules.iter().count()
    }
}

pub struct Signature(pub String);

pub struct SigSetBuilder {
    signatures: Vec<Signature>,
}

impl SigSetBuilder {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn add_sig(mut self, signatures: Vec<Signature>) -> Self {
        self.signatures.extend(signatures);
        self
    }

    pub fn add_sigs(mut self, signature: Signature) -> Self {
        self.signatures.push(signature);
        self
    }

    pub fn build(self) -> Result<SigSet> {
        let mut compiler = yara_x::Compiler::new();
        for signature in self.signatures {
            compiler.add_source(signature.0.as_str())?;
        }
        let rules = compiler.build();

        let signature_set = SigSet { rules };
        Ok(signature_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builder_valid_signature() {
        let signature_set = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: true }".to_string()))
            .build()
            .unwrap();

        assert_eq!(1, signature_set.count());
    }

    #[test]
    fn builder_invalid_signature() {
        let result = SigSetBuilder::new()
            .add_sigs(Signature("rule test { condition: ".to_string()))
            .build();
        assert!(result.is_err());
    }
}
