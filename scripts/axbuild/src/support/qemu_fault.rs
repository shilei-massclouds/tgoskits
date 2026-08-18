//! QMP fault capture used only by the opt-in KernDiff QEMU profile.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use ostool::run::qemu::QemuConfig;

const QMP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const QMP_IO_POLL: Duration = Duration::from_millis(250);
const DIAGNOSTIC_PAGE_BYTES: usize = 4096;
const DIAGNOSTIC_MAGIC: u32 = 0x4b44_5744;
const DIAGNOSTIC_VERSION: u32 = 1;
const MAX_DIAGNOSTIC_CPUS: usize = 64;
const WATCHDOG_MARKER_PREFIX: &str = "STARRY_KERNEL_WATCHDOG version=1 state=armed ";
const WATCHDOG_PMEMSAVE_REQUEST_ID: &str = "kerndiff-watchdog-pmemsave";
static SOCKET_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static DIAGNOSTIC_PAGE_PA: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct QemuFaultPaths {
    socket: PathBuf,
}

impl QemuFaultPaths {
    pub(crate) fn new(workspace: &Path) -> anyhow::Result<Self> {
        DIAGNOSTIC_PAGE_PA.store(0, Ordering::Release);
        let root = workspace.join("tmp/axbuild/qmp");
        fs::create_dir_all(&root)?;
        let sequence = SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            socket: root.join(format!("kerndiff-{}-{sequence}.sock", std::process::id())),
        })
    }
}

/// Observes one complete guest output line from the existing coverage tee.
pub(crate) fn observe_guest_output_line(line: &str) {
    let normalized = line.trim_start_matches(['\u{1b}', '[']);
    let Some(marker) = normalized.find(WATCHDOG_MARKER_PREFIX) else {
        return;
    };
    let fields = &normalized[marker + WATCHDOG_MARKER_PREFIX.len()..];
    let Some(encoded) = fields
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("diagnostic_page_pa="))
    else {
        return;
    };
    let Some(hexadecimal) = encoded.strip_prefix("0x") else {
        return;
    };
    if let Ok(address) = u64::from_str_radix(hexadecimal, 16)
        && address != 0
    {
        DIAGNOSTIC_PAGE_PA.store(address, Ordering::Release);
    }
}

pub(crate) fn enabled() -> bool {
    std::env::var("KERNDIFF_QMP_FAULTS")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "y" | "yes" | "true" | "on"))
}

pub(crate) fn apply_qmp(qemu: &mut QemuConfig, paths: &QemuFaultPaths) -> anyhow::Result<()> {
    match fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    qemu.args.extend([
        "-qmp".to_string(),
        format!("unix:{},server=on,wait=off", paths.socket.display()),
    ]);
    Ok(())
}

pub(crate) struct QemuFaultCapture {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<anyhow::Result<Vec<CapturedEvent>>>>,
}

impl QemuFaultCapture {
    pub(crate) fn install(paths: &QemuFaultPaths, case: &str) -> Self {
        let socket = paths.socket.clone();
        let thread_socket = socket.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let case = case.to_string();
        let reader =
            std::thread::spawn(move || capture_events(&thread_socket, &case, &thread_stop));
        Self {
            socket,
            stop,
            reader: Some(reader),
        }
    }

    pub(crate) fn finish(mut self) -> anyhow::Result<Vec<serde_json::Value>> {
        self.stop.store(true, Ordering::Release);
        let result = self
            .reader
            .take()
            .expect("QMP reader handle missing")
            .join()
            .map_err(|_| anyhow::anyhow!("QMP reader thread panicked"))??;
        let _ = fs::remove_file(&self.socket);
        Ok(result.into_iter().map(CapturedEvent::into_json).collect())
    }
}

impl Drop for QemuFaultCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = fs::remove_file(&self.socket);
    }
}

#[derive(Debug)]
struct CapturedEvent {
    case: String,
    event: String,
    elapsed_ms: u64,
    action: Option<String>,
    diagnostic: Option<serde_json::Value>,
    raw_error: Option<String>,
}

impl CapturedEvent {
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "schema_name": "axbuild-qemu-fault",
            "schema_version": 1,
            "case": self.case,
            "elapsed_ms": self.elapsed_ms,
            "event": self.event,
            "action": self.action,
            "diagnostic": self.diagnostic,
            "raw_error": self.raw_error,
        })
    }
}

fn capture_events(
    socket: &Path,
    case: &str,
    stop: &AtomicBool,
) -> anyhow::Result<Vec<CapturedEvent>> {
    let started = Instant::now();
    let mut stream = connect_qmp(socket, stop)?;
    stream.set_read_timeout(Some(QMP_IO_POLL))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let greeting = read_qmp_message(&mut reader, stop)?;
    if greeting.get("QMP").is_none() {
        bail!("QMP greeting is missing the QMP field")
    }
    write_qmp_command(&mut stream, "qmp_capabilities")?;
    wait_for_return(&mut reader, stop)?;

    let mut events = Vec::new();
    while !stop.load(Ordering::Acquire) {
        let value = match read_qmp_message(&mut reader, stop) {
            Ok(value) => value,
            Err(error) if is_disconnect(&error) => break,
            Err(error) => return Err(error),
        };
        let Some(mut event) = parse_event(&value, case, started.elapsed()) else {
            continue;
        };
        let terminal = matches!(event.event.as_str(), "WATCHDOG" | "GUEST_PANICKED");
        if event.event == "WATCHDOG" {
            match capture_watchdog_diagnostic(&mut stream, &mut reader, socket, stop) {
                Ok(diagnostic) => event.diagnostic = Some(diagnostic),
                Err(error) => event.raw_error = Some(format!("{error:#}")),
            }
        }
        events.push(event);
        if terminal {
            // WATCHDOG uses action=pause, and pvpanic may also leave QEMU
            // running. Quit only after the authoritative event is captured.
            let _ = write_qmp_command(&mut stream, "quit");
            break;
        }
    }
    Ok(events)
}

fn connect_qmp(socket: &Path, stop: &AtomicBool) -> anyhow::Result<UnixStream> {
    let deadline = Instant::now() + QMP_CONNECT_TIMEOUT;
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if !stop.load(Ordering::Acquire)
                    && Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                    ) =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to connect QMP socket {}", socket.display()));
            }
        }
    }
}

fn read_qmp_message(
    reader: &mut BufReader<UnixStream>,
    stop: &AtomicBool,
) -> anyhow::Result<serde_json::Value> {
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => bail!("QMP socket closed"),
            Ok(_) => {
                return serde_json::from_str(line.trim_end()).context("QMP emitted invalid JSON");
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if stop.load(Ordering::Acquire) {
                    bail!("QMP capture stopped")
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_for_return(reader: &mut BufReader<UnixStream>, stop: &AtomicBool) -> anyhow::Result<()> {
    loop {
        let value = read_qmp_message(reader, stop)?;
        if value.get("return").is_some() {
            return Ok(());
        }
        if let Some(error) = value.get("error") {
            bail!("QMP capability negotiation failed: {error}")
        }
    }
}

fn write_qmp_command(stream: &mut UnixStream, command: &str) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *stream, &serde_json::json!({"execute": command}))?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn capture_watchdog_diagnostic(
    stream: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    socket: &Path,
    stop: &AtomicBool,
) -> anyhow::Result<serde_json::Value> {
    let address = DIAGNOSTIC_PAGE_PA.load(Ordering::Acquire);
    if address == 0 {
        bail!("watchdog diagnostic page marker was not observed")
    }
    let output = socket.with_extension("diagnostic-page.bin");
    let _ = fs::remove_file(&output);
    let command = watchdog_diagnostic_page_request(address, &output);
    serde_json::to_writer(&mut *stream, &command)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    wait_for_command_return(reader, stop, WATCHDOG_PMEMSAVE_REQUEST_ID)?;
    let encoded = fs::read(&output).with_context(|| {
        format!(
            "failed to read watchdog diagnostic page {}",
            output.display()
        )
    });
    let _ = fs::remove_file(&output);
    decode_diagnostic_page(&encoded?)
}

fn watchdog_diagnostic_page_request(address: u64, output: &Path) -> serde_json::Value {
    serde_json::json!({
        "execute": "pmemsave",
        "arguments": {
            "val": address,
            "size": DIAGNOSTIC_PAGE_BYTES,
            "filename": output,
        },
        "id": WATCHDOG_PMEMSAVE_REQUEST_ID,
    })
}

fn wait_for_command_return(
    reader: &mut BufReader<UnixStream>,
    stop: &AtomicBool,
    command_id: &str,
) -> anyhow::Result<()> {
    loop {
        let value = read_qmp_message(reader, stop)?;
        if value.get("id").and_then(serde_json::Value::as_str) != Some(command_id) {
            continue;
        }
        if value.get("return").is_some() {
            return Ok(());
        }
        if let Some(error) = value.get("error") {
            bail!("QMP pmemsave failed: {error}")
        }
        bail!("QMP pmemsave returned an invalid response")
    }
}

fn decode_diagnostic_page(encoded: &[u8]) -> anyhow::Result<serde_json::Value> {
    if encoded.len() != DIAGNOSTIC_PAGE_BYTES {
        bail!(
            "watchdog diagnostic page has invalid length {}",
            encoded.len()
        )
    }
    let magic = read_u32(encoded, 0)?;
    let version = read_u32(encoded, 4)?;
    let size = read_u32(encoded, 8)?;
    let max_cpus = usize::try_from(read_u32(encoded, 12)?).unwrap_or(usize::MAX);
    if magic != DIAGNOSTIC_MAGIC
        || version != DIAGNOSTIC_VERSION
        || usize::try_from(size).unwrap_or(usize::MAX) > DIAGNOSTIC_PAGE_BYTES
        || max_cpus != MAX_DIAGNOSTIC_CPUS
    {
        bail!(
            "watchdog diagnostic header is invalid: magic={magic:#x} version={version} \
             size={size} max_cpus={max_cpus}"
        )
    }
    let boot_epoch = read_u64(encoded, 16)?;
    let online_mask = read_u64(encoded, 24)?;
    let stale_mask = read_u64(encoded, 32)?;
    let scheduler_offset = 40;
    let irq_offset = scheduler_offset + MAX_DIAGNOSTIC_CPUS * 8;
    let progress_offset = irq_offset + MAX_DIAGNOSTIC_CPUS * 8;
    let mut cpus = Vec::new();
    for cpu in 0..MAX_DIAGNOSTIC_CPUS {
        if online_mask & (1u64 << cpu) == 0 {
            continue;
        }
        cpus.push(serde_json::json!({
            "cpu": cpu,
            "scheduler_epoch": read_u64(encoded, scheduler_offset + cpu * 8)?,
            "irq_epoch": read_u64(encoded, irq_offset + cpu * 8)?,
            "last_progress_ns": read_u64(encoded, progress_offset + cpu * 8)?,
        }));
    }
    Ok(serde_json::json!({
        "schema_name": "starry-kernel-watchdog-diagnostic",
        "schema_version": version,
        "boot_epoch": boot_epoch,
        "online_cpu_mask": format!("{online_mask:#x}"),
        "stuck_cpu_mask": format!("{stale_mask:#x}"),
        "cpus": cpus,
    }))
}

fn read_u32(encoded: &[u8], offset: usize) -> anyhow::Result<u32> {
    let bytes = encoded
        .get(offset..offset + 4)
        .context("watchdog diagnostic u32 is truncated")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(encoded: &[u8], offset: usize) -> anyhow::Result<u64> {
    let bytes = encoded
        .get(offset..offset + 8)
        .context("watchdog diagnostic u64 is truncated")?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn parse_event(value: &serde_json::Value, case: &str, elapsed: Duration) -> Option<CapturedEvent> {
    let event = value.get("event")?.as_str()?;
    if !matches!(event, "WATCHDOG" | "GUEST_PANICKED" | "RESET" | "SHUTDOWN") {
        return None;
    }
    let action = value
        .get("data")
        .and_then(|data| data.get("action"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    Some(CapturedEvent {
        case: case.to_string(),
        event: event.to_string(),
        elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        action,
        diagnostic: None,
        raw_error: None,
    })
}

fn is_disconnect(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}");
    message.contains("QMP socket closed") || message.contains("QMP capture stopped")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_authoritative_fault_events() {
        let watchdog = parse_event(
            &serde_json::json!({"event": "WATCHDOG", "data": {"action": "pause"}}),
            "kerndiff",
            Duration::from_millis(61_000),
        )
        .unwrap()
        .into_json();
        assert_eq!(watchdog["event"], "WATCHDOG");
        assert_eq!(watchdog["action"], "pause");
        assert_eq!(watchdog["elapsed_ms"], 61_000);
        assert!(
            parse_event(
                &serde_json::json!({"event": "STOP"}),
                "kerndiff",
                Duration::ZERO,
            )
            .is_none()
        );
    }

    #[test]
    fn panic_reset_and_shutdown_keep_case_identity() {
        for name in ["GUEST_PANICKED", "RESET", "SHUTDOWN"] {
            let event = parse_event(
                &serde_json::json!({"event": name}),
                "kerndiff-case",
                Duration::from_millis(9),
            )
            .unwrap()
            .into_json();
            assert_eq!(event["case"], "kerndiff-case");
            assert_eq!(event["event"], name);
        }
    }

    #[test]
    fn builds_physical_watchdog_diagnostic_page_request() {
        let output = Path::new("/tmp/watchdog-diagnostic-page.bin");

        let request = watchdog_diagnostic_page_request(0x1234_5000, output);

        assert_eq!(
            request,
            serde_json::json!({
                "execute": "pmemsave",
                "arguments": {
                    "val": 0x1234_5000,
                    "size": 4096,
                    "filename": output,
                },
                "id": "kerndiff-watchdog-pmemsave",
            })
        );
    }

    #[test]
    fn marker_and_diagnostic_page_round_trip() {
        DIAGNOSTIC_PAGE_PA.store(0, Ordering::Release);
        observe_guest_output_line(
            "STARRY_KERNEL_WATCHDOG version=1 state=armed timeout_seconds=60 online_mask=0x1 \
             diagnostic_page_pa=0x12345000 boot_epoch=9",
        );
        assert_eq!(DIAGNOSTIC_PAGE_PA.load(Ordering::Acquire), 0x1234_5000);

        let mut page = vec![0u8; DIAGNOSTIC_PAGE_BYTES];
        page[0..4].copy_from_slice(&DIAGNOSTIC_MAGIC.to_le_bytes());
        page[4..8].copy_from_slice(&DIAGNOSTIC_VERSION.to_le_bytes());
        page[8..12].copy_from_slice(&(1576u32).to_le_bytes());
        page[12..16].copy_from_slice(&(64u32).to_le_bytes());
        page[16..24].copy_from_slice(&(99u64).to_le_bytes());
        page[24..32].copy_from_slice(&(0b101u64).to_le_bytes());
        page[32..40].copy_from_slice(&(0b100u64).to_le_bytes());
        page[40..48].copy_from_slice(&(7u64).to_le_bytes());
        page[40 + 2 * 8..40 + 3 * 8].copy_from_slice(&(8u64).to_le_bytes());
        let diagnostic = decode_diagnostic_page(&page).unwrap();
        assert_eq!(diagnostic["boot_epoch"], 99);
        assert_eq!(diagnostic["online_cpu_mask"], "0x5");
        assert_eq!(diagnostic["stuck_cpu_mask"], "0x4");
        assert_eq!(diagnostic["cpus"].as_array().unwrap().len(), 2);
        assert_eq!(diagnostic["cpus"][1]["scheduler_epoch"], 8);
    }
}
