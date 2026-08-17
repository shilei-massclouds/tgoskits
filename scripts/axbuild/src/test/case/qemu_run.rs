use std::path::Path;

use ostool::{build::config::Cargo, run::qemu::QemuConfig};

use super::{
    assets::{remove_case_rootfs_copy, remove_case_run_dir},
    types::{PreparedCaseAssets, RunPreparedQemuCaseOptions},
};
use crate::{context::AppContext, test::timing};

const QEMU_CASE_EVENT_SCHEMA: &str = "axbuild-qemu-case";
const QEMU_CASE_EVENT_VERSION: u64 = 1;

pub(crate) async fn run_qemu_with_prepared_case_assets(
    app: &mut AppContext,
    cargo: &Cargo,
    qemu: QemuConfig,
    capture_backtrace: Option<crate::backtrace::BacktraceQemuCapture>,
    qemu_config_path: &Path,
    prepared_assets: PreparedCaseAssets,
    options: RunPreparedQemuCaseOptions,
) -> anyhow::Result<()> {
    println!(
        "  prepare assets: {:.2?} (pipeline={}, cache={})",
        options.prepare_elapsed,
        prepared_assets.pipeline.as_str(),
        if prepared_assets.cache_hit {
            "hit"
        } else {
            "miss"
        }
    );
    println!(
        "  qemu config: {} (timeout={})",
        qemu_config_path.display(),
        super::super::qemu::qemu_timeout_summary(&qemu)
    );
    println!("  rootfs: {}", prepared_assets.rootfs_path.display());
    let effective_timeout = qemu.timeout.filter(|timeout| *timeout > 0);
    print_qemu_case_event(qemu_case_start_event(&options.case_name, effective_timeout));

    let qemu_started = std::time::Instant::now();
    let result = app
        .run_qemu_with_axtest_coverage(cargo, qemu, capture_backtrace)
        .await;
    let qemu_elapsed = qemu_started.elapsed();
    print_qemu_case_event(qemu_case_end_event(
        &options.case_name,
        effective_timeout,
        qemu_elapsed,
        &result,
    ));
    println!("  qemu run: {:.2?}", qemu_elapsed);
    if let Some(mut fields) = options.qemu_timing_fields {
        fields.push(("phase", "qemu-run".to_string()));
        timing::print_timing_line("qemu-case", &fields, qemu_elapsed);
    }

    remove_case_rootfs_copy(prepared_assets.rootfs_copy_to_remove.as_deref());
    remove_case_run_dir(prepared_assets.run_dir_to_remove.as_deref());
    result
}

fn qemu_case_start_event(case: &str, timeout_seconds: Option<u64>) -> serde_json::Value {
    serde_json::json!({
        "schema_name": QEMU_CASE_EVENT_SCHEMA,
        "schema_version": QEMU_CASE_EVENT_VERSION,
        "event": "start",
        "case": case,
        "timeout_seconds": timeout_seconds,
    })
}

fn qemu_case_end_event(
    case: &str,
    timeout_seconds: Option<u64>,
    elapsed: std::time::Duration,
    result: &anyhow::Result<()>,
) -> serde_json::Value {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let (outcome, error_summary) = match result {
        Ok(()) => ("passed", None),
        Err(error) => ("failed", Some(format!("{error:#}"))),
    };
    serde_json::json!({
        "schema_name": QEMU_CASE_EVENT_SCHEMA,
        "schema_version": QEMU_CASE_EVENT_VERSION,
        "event": "end",
        "case": case,
        "timeout_seconds": timeout_seconds,
        "elapsed_ms": elapsed_ms,
        "result": outcome,
        "error_summary": error_summary,
    })
}

fn print_qemu_case_event(event: serde_json::Value) {
    println!("[axbuild] qemu-case-event {event}");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{qemu_case_end_event, qemu_case_start_event};

    #[test]
    fn qemu_case_events_are_versioned_and_preserve_raw_error() {
        let start = qemu_case_start_event("kerndiff", Some(300));
        assert_eq!(start["schema_name"], "axbuild-qemu-case");
        assert_eq!(start["schema_version"], 1);
        assert_eq!(start["event"], "start");
        assert_eq!(start["case"], "kerndiff");
        assert_eq!(start["timeout_seconds"], 300);

        let result = Err(anyhow::anyhow!("QEMU timed out after 300 seconds"));
        let end = qemu_case_end_event(
            "kerndiff",
            Some(300),
            Duration::from_millis(300_012),
            &result,
        );
        assert_eq!(end["event"], "end");
        assert_eq!(end["elapsed_ms"], 300_012);
        assert_eq!(end["result"], "failed");
        assert_eq!(end["error_summary"], "QEMU timed out after 300 seconds");
    }
}
