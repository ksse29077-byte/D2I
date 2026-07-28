//! Deterministic Rust baseline and removable native candidate for hot kernels.

mod benchmark;

pub use benchmark::{
    run_kernel_benchmark, BackendBenchmark, CandidateConfig, KernelBenchmarkOptions,
    KernelBenchmarkReport,
};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Symptom text matched.
pub const MATCH_SYMPTOM: u8 = 0b001;
/// Error code matched.
pub const MATCH_ERROR_CODE: u8 = 0b010;
/// Equipment type matched.
pub const MATCH_EQUIPMENT: u8 = 0b100;
const VALID_MATCH_MASK: u8 = MATCH_SYMPTOM | MATCH_ERROR_CODE | MATCH_EQUIPMENT;

/// Invalid input to the deterministic score kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    LengthMismatch { masks: usize, scores: usize },
    InvalidMask { index: usize, mask: u8 },
}

impl Display for KernelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthMismatch { masks, scores } => {
                write!(
                    formatter,
                    "score output length {scores} does not match mask length {masks}"
                )
            }
            Self::InvalidMask { index, mask } => {
                write!(
                    formatter,
                    "match mask {mask:#04x} at index {index} is invalid"
                )
            }
        }
    }
}

impl Error for KernelError {}

/// Scores each three-bit match mask into caller-owned output.
pub fn score_match_masks_into(match_masks: &[u8], scores: &mut [u16]) -> Result<(), KernelError> {
    if match_masks.len() != scores.len() {
        return Err(KernelError::LengthMismatch {
            masks: match_masks.len(),
            scores: scores.len(),
        });
    }
    for (index, (mask, score)) in match_masks.iter().zip(scores.iter_mut()).enumerate() {
        if mask & !VALID_MATCH_MASK != 0 {
            return Err(KernelError::InvalidMask { index, mask: *mask });
        }
        *score = u16::from(mask & MATCH_SYMPTOM != 0) * 45
            + u16::from(mask & MATCH_ERROR_CODE != 0) * 45
            + u16::from(mask & MATCH_EQUIPMENT != 0) * 10;
    }
    Ok(())
}

/// Allocates and returns deterministic integer scores for the supplied masks.
pub fn score_match_masks(match_masks: &[u8]) -> Result<Vec<u16>, KernelError> {
    let mut scores = vec![0_u16; match_masks.len()];
    score_match_masks_into(match_masks, &mut scores)?;
    Ok(scores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_valid_mask_has_the_expected_integer_score() {
        let masks = [0, 1, 2, 3, 4, 5, 6, 7];
        let scores = match score_match_masks(&masks) {
            Ok(scores) => scores,
            Err(error) => panic!("valid score input failed: {error}"),
        };
        assert_eq!(scores, [0, 45, 45, 90, 10, 55, 55, 100]);
    }

    #[test]
    fn malformed_masks_and_output_lengths_are_rejected() {
        let mut short = [0_u16; 1];
        assert!(matches!(
            score_match_masks_into(&[1, 2], &mut short),
            Err(KernelError::LengthMismatch { .. })
        ));
        assert!(matches!(
            score_match_masks(&[0x80]),
            Err(KernelError::InvalidMask {
                index: 0,
                mask: 0x80
            })
        ));
    }
}
