use crate::error::Error;

#[cfg(target_arch = "x86_64")]
const REQUIRED: &[&str] = &["aes", "pclmulqdq", "bmi1", "adx", "avx", "avx2"];
#[cfg(target_arch = "aarch64")]
const REQUIRED: &[&str] = &["neon", "aes", "pmull", "sha2"];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const REQUIRED: &[&str] = &[];

#[cfg(target_arch = "x86_64")]
fn detected(feature: &str) -> bool {
    match feature {
        "aes" => std::arch::is_x86_feature_detected!("aes"),
        "pclmulqdq" => std::arch::is_x86_feature_detected!("pclmulqdq"),
        "bmi1" => std::arch::is_x86_feature_detected!("bmi1"),
        "adx" => std::arch::is_x86_feature_detected!("adx"),
        "avx" => std::arch::is_x86_feature_detected!("avx"),
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        _ => false,
    }
}

#[cfg(target_arch = "aarch64")]
fn detected(feature: &str) -> bool {
    match feature {
        "neon" => std::arch::is_aarch64_feature_detected!("neon"),
        "aes" => std::arch::is_aarch64_feature_detected!("aes"),
        "pmull" => std::arch::is_aarch64_feature_detected!("pmull"),
        "sha2" => std::arch::is_aarch64_feature_detected!("sha2"),
        _ => false,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detected(_feature: &str) -> bool {
    false
}

fn first_missing(required: &[&'static str], has: impl Fn(&str) -> bool) -> Option<&'static str> {
    required.iter().copied().find(|feature| !has(feature))
}

/// Fail with a typed error before the cryptographic provider asserts on missing CPU features.
pub fn require() -> Result<(), Error> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err(Error::UnsupportedHardware {
            feature: "a supported processor architecture",
        });
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    match first_missing(REQUIRED, detected) {
        Some(feature) => Err(Error::UnsupportedHardware { feature }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_missing_feature_is_named() {
        assert_eq!(first_missing(&["aes", "avx2"], |feature| feature == "aes"), Some("avx2"));
        assert_eq!(first_missing(&["aes"], |_| true), None);
    }

    #[test]
    fn this_host_satisfies_the_provider() {
        require().expect("test host supports Graviola");
        let _ = <graviola::hashing::Sha256 as graviola::hashing::Hash>::hash(b"");
    }
}
