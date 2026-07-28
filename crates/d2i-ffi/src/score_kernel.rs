use crate::loader::verify_library;
use crate::{AbiCopyMetrics, D2iStatus, FfiError, NativeModulePolicy};
use libloading::{Library, Symbol};
use std::path::Path;

const SCORE_SYMBOL: &[u8] = b"d2i_score_match_masks_v1\0";
const VALID_MATCH_MASK: u8 = 0b111;

type ScoreMatchMasksV1 = unsafe extern "C" fn(
    match_masks: *const u8,
    item_count: u64,
    scores: *mut u16,
    score_capacity: u64,
) -> D2iStatus;

/// Loaded stateless native implementation of the Phase 7 score kernel.
pub struct NativeScoreKernel {
    _library: Library,
    score: ScoreMatchMasksV1,
    maximum_items: u64,
    metrics: AbiCopyMetrics,
    library_sha256: String,
}

impl NativeScoreKernel {
    /// Verifies and loads the fixed score-kernel symbol from a native library.
    pub fn load(path: &Path, policy: &NativeModulePolicy) -> Result<Self, FfiError> {
        let (canonical_path, library_sha256) = verify_library(path, policy)?;
        // SAFETY: The canonical regular file is size-bounded and hash-allowlisted.
        let library = unsafe { Library::new(&canonical_path) }
            .map_err(|error| FfiError::Load(error.to_string()))?;
        let score: ScoreMatchMasksV1 = {
            // SAFETY: The symbol has a fixed published C ABI signature and the
            // owning library remains live in NativeScoreKernel.
            let symbol: Symbol<'_, ScoreMatchMasksV1> = unsafe { library.get(SCORE_SYMBOL) }
                .map_err(|error| FfiError::MissingSymbol(error.to_string()))?;
            *symbol
        };
        let maximum_items = policy
            .maximum_input_bytes
            .min(policy.maximum_output_bytes / 2);
        Ok(Self {
            _library: library,
            score,
            maximum_items,
            metrics: AbiCopyMetrics::default(),
            library_sha256,
        })
    }

    /// Scores match masks into caller-owned output without an ABI boundary copy.
    pub fn score_into(&mut self, match_masks: &[u8], scores: &mut [u16]) -> Result<(), FfiError> {
        let item_count = u64::try_from(match_masks.len())
            .map_err(|_| FfiError::InvalidBuffer("item count exceeds u64".to_owned()))?;
        if item_count > self.maximum_items {
            return Err(FfiError::InvalidBuffer(
                "score kernel exceeds configured item limit".to_owned(),
            ));
        }
        if scores.len() < match_masks.len() {
            return Err(FfiError::BufferTooSmall {
                required: item_count.saturating_mul(2),
                capacity: u64::try_from(scores.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            });
        }
        if match_masks.iter().any(|mask| mask & !VALID_MATCH_MASK != 0) {
            return Err(FfiError::InvalidBuffer(
                "score kernel input contains unknown match bits".to_owned(),
            ));
        }

        self.metrics.input_view_count = self.metrics.input_view_count.saturating_add(1);
        self.metrics.input_view_bytes = self.metrics.input_view_bytes.saturating_add(item_count);
        self.metrics.output_view_count = self.metrics.output_view_count.saturating_add(1);
        self.metrics.output_view_bytes = self
            .metrics
            .output_view_bytes
            .saturating_add(item_count.saturating_mul(2));
        // SAFETY: Both slices remain live and exclusively borrowed as required
        // for this synchronous call. Lengths and match bits were validated.
        let status = unsafe {
            (self.score)(
                match_masks.as_ptr(),
                item_count,
                scores.as_mut_ptr(),
                u64::try_from(scores.len()).unwrap_or(u64::MAX),
            )
        };
        if status == D2iStatus::OK {
            Ok(())
        } else if status == D2iStatus::BUFFER_TOO_SMALL {
            Err(FfiError::BufferTooSmall {
                required: item_count.saturating_mul(2),
                capacity: u64::try_from(scores.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            })
        } else {
            Err(FfiError::ModuleStatus {
                operation: "score",
                code: status.0,
            })
        }
    }

    /// Returns cumulative borrowed-view and boundary-copy metrics.
    #[must_use]
    pub fn copy_metrics(&self) -> &AbiCopyMetrics {
        &self.metrics
    }

    /// Returns the verified primary library hash.
    #[must_use]
    pub fn library_sha256(&self) -> &str {
        &self.library_sha256
    }
}
