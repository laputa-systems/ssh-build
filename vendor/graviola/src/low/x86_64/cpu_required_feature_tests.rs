// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#[test]
fn rejects_disabled_bmi2_and_popcnt() {
    if std::env::var_os("GRAVIOLA_TEST_DISABLED_FEATURE").is_some() {
        assert!(!super::is_cpu_supported());
        return;
    }
    assert!(super::is_cpu_supported());
    for feature in ["bmi2", "popcnt"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "low::x86_64::cpu::required_feature_tests::rejects_disabled_bmi2_and_popcnt",
            ])
            .env("GRAVIOLA_TEST_DISABLED_FEATURE", feature)
            .env(format!("GRAVIOLA_CPU_DISABLE_{feature}"), "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
