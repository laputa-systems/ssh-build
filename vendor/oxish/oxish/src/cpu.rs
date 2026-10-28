//! CPU feature floor required by Graviola
//!
//! Graviola asserts its required features on first use; checking up front turns an unsupported
//! machine into a clear startup error instead of an abort in the middle of a handshake.

use core::fmt;

/// A CPU feature Graviola needs that this machine lacks
#[derive(Debug)]
pub struct MissingCpuFeature(pub &'static str);

impl fmt::Display for MissingCpuFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this CPU lacks `{}`, which Graviola requires (x86-64 needs a Broadwell-class core: \
             AES-NI, PCLMULQDQ, BMI1, ADX, AVX2; aarch64 needs NEON with the AES, PMULL and SHA2 \
             extensions)",
            self.0
        )
    }
}

impl core::error::Error for MissingCpuFeature {}

/// Fail unless the CPU has every feature Graviola requires
pub fn require_supported_cpu() -> Result<(), MissingCpuFeature> {
    #[cfg(target_arch = "x86_64")]
    {
        let features = [
            ("aes", is_x86_feature_detected!("aes")),
            ("pclmulqdq", is_x86_feature_detected!("pclmulqdq")),
            ("bmi1", is_x86_feature_detected!("bmi1")),
            ("adx", is_x86_feature_detected!("adx")),
            ("avx", is_x86_feature_detected!("avx")),
            ("avx2", is_x86_feature_detected!("avx2")),
        ];
        if let Some((name, _)) = features.iter().find(|(_, present)| !present) {
            return Err(MissingCpuFeature(name));
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = [
            ("neon", std::arch::is_aarch64_feature_detected!("neon")),
            ("aes", std::arch::is_aarch64_feature_detected!("aes")),
            ("pmull", std::arch::is_aarch64_feature_detected!("pmull")),
            ("sha2", std::arch::is_aarch64_feature_detected!("sha2")),
        ];
        if let Some((name, _)) = features.iter().find(|(_, present)| !present) {
            return Err(MissingCpuFeature(name));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_test_machine_meets_the_floor() {
        super::require_supported_cpu().unwrap();
    }
}
