use ark_bn254::Fr as Bn254Fr;
use ark_relations::r1cs::ConstraintSynthesizer;

/// Arkworks `ConstraintSynthesizer` wrapper for a pre-computed Circom witness.
///
/// The proving key already encodes all constraints from the Circom compilation.
/// This struct only registers the witness variable assignment in the correct
/// order so arkworks can perform the MSM operations during proving.
///
/// Witness layout (Circom convention):
///   index 0                         — constant 1
///   indices 1..=num_public_signals  — public signals
///   indices (num_public+1)..        — private witness
pub struct WitnessCircuit {
    pub witness: Vec<Bn254Fr>,
    pub num_public_signals: usize,
}

impl ConstraintSynthesizer<Bn254Fr> for WitnessCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Bn254Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        for i in 1..=self.num_public_signals {
            if i < self.witness.len() {
                let _ = cs.new_input_variable(|| Ok(self.witness[i]))?;
            }
        }
        for signal in self.witness.iter().skip(self.num_public_signals + 1) {
            let _ = cs.new_witness_variable(|| Ok(*signal))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_stores_fields() {
        let witness = vec![
            Bn254Fr::from(1u64),
            Bn254Fr::from(100u64),
            Bn254Fr::from(200u64),
        ];
        let circuit = WitnessCircuit {
            witness: witness.clone(),
            num_public_signals: 1,
        };
        assert_eq!(circuit.witness.len(), 3);
        assert_eq!(circuit.num_public_signals, 1);
    }

    #[test]
    fn test_circuit_empty_witness() {
        let circuit = WitnessCircuit {
            witness: vec![],
            num_public_signals: 0,
        };
        assert_eq!(circuit.witness.len(), 0);
    }
}
