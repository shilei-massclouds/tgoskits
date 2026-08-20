use super::*;

#[test]
fn boot_probe_precedes_coverage_and_installs_the_guest_start_stop_contract() {
    assert_eq!(
        resolve_qemu_run_contract(true, true, true).unwrap(),
        QemuRunContract::BootProbe
    );

    let failures = vec!["(?i)panic".to_string()];
    let mut qemu = QemuConfig {
        success_regex: vec!["AXTEST_COVERAGE_DONE".to_string()],
        fail_regex: failures.clone(),
        ..QemuConfig::default()
    };
    let host_success = apply_boot_probe_success_contract(&mut qemu);

    assert_eq!(qemu.success_regex, host_success);
    assert_eq!(qemu.fail_regex, failures);
    assert_eq!(
        host_success,
        [crate::support::qemu_fault::BOOT_PROBE_SUCCESS_REGEX.to_string()]
    );
}

#[test]
fn boot_probe_without_qmp_fault_capture_fails_closed() {
    let error = resolve_qemu_run_contract(true, false, true).unwrap_err();

    assert_eq!(
        error.to_string(),
        "KERNDIFF_BOOT_PROBE=1 requires KERNDIFF_QMP_FAULTS=1"
    );
}

#[test]
fn ordinary_coverage_keeps_the_profraw_contract() {
    assert_eq!(
        resolve_qemu_run_contract(false, false, true).unwrap(),
        QemuRunContract::AxtestCoverage
    );

    let error = crate::support::qemu_success::combine_qemu_and_coverage_results(
        Ok(()),
        Err(anyhow::anyhow!("no coverage profile was captured")),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "no coverage profile was captured");
}

mod arceos;
mod axvisor;
mod board_request;
mod common;
mod snapshot;
mod starry;
mod workspace;
