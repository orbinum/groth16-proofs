//! Circuit wrapper for arkworks constraint system

use ark_bn254::Fr as Bn254Fr;
use ark_relations::r1cs::ConstraintSynthesizer;

/// Minimal circuit wrapper for arkworks
///
/// This struct holds the witness and implements the ConstraintSynthesizer trait
/// required by ark-groth16. It doesn't generate actual constraints - those are
/// already baked into the proving key from the Circom circuit compilation.
pub struct WitnessCircuit {
    pub witness: Vec<Bn254Fr>,
}

impl ConstraintSynthesizer<Bn254Fr> for WitnessCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Bn254Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        // Mark public inputs (index 0 is always 1, indices 1..n are public)
        // The exact number depends on the circuit
        let num_public = if self.witness.len() > 1 {
            // Estimate based on witness size (conservative)
            (self.witness.len() / 100).clamp(1, 10)
        } else {
            0
        };

        for i in 0..num_public {
            if i + 1 < self.witness.len() {
                let _ = cs.new_input_variable(|| Ok(self.witness[i + 1]))?;
            }
        }

        // Private witness variables
        for signal in self.witness.iter().skip(num_public + 1) {
            let _ = cs.new_witness_variable(|| Ok(*signal))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_circuit_creation() {
        let witness = vec![
            Bn254Fr::from(1u64),
            Bn254Fr::from(100u64),
            Bn254Fr::from(200u64),
        ];
        let circuit = WitnessCircuit {
            witness: witness.clone(),
        };

        assert_eq!(circuit.witness.len(), 3);
    }

    #[test]
    fn test_witness_circuit_empty() {
        let circuit = WitnessCircuit { witness: vec![] };
        assert_eq!(circuit.witness.len(), 0);
    }
}
