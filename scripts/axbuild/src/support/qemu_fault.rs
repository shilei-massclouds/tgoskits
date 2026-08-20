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
const MAX_GUEST_OUTPUT_LINE_BYTES: usize = 4096;
const DIAGNOSTIC_PAGE_BYTES: usize = 4096;
const DIAGNOSTIC_MAGIC: u32 = 0x4b44_5744;
const DIAGNOSTIC_VERSION_V1: u32 = 1;
const DIAGNOSTIC_VERSION_V2: u32 = 2;
const DIAGNOSTIC_VERSION_V3: u32 = 3;
const DIAGNOSTIC_VERSION_V4: u32 = 4;
const MAX_DIAGNOSTIC_CPUS: usize = 64;
const V1_DIAGNOSTIC_BYTES: usize = 1576;
const V2_DIAGNOSTIC_BYTES: usize = 1696;
const V3_DIAGNOSTIC_BYTES: usize = 1752;
const V4_DIAGNOSTIC_BYTES: usize = 1808;
const BOOT_PHASE_NAMES: [&str; 12] = [
    "watchdog-armed",
    "filesystem-init-start",
    "filesystem-init-ready",
    "secondary-startup-start",
    "secondary-startup-ready",
    "all-cpus-initialized",
    "ipi-ready",
    "smp-filesystem-online",
    "watchdog-handoff",
    "kernel-main",
    "userspace-init",
    "shell-ready",
];
const BOOTSTRAP_CHECKPOINT_NAMES: [&str; 6] = [
    "feeder-spawn-requested",
    "feeder-task-initialized",
    "feeder-spawn-returned",
    "feeder-entered",
    "feeder-affinity-ready",
    "feeder-first-poll-complete",
];
const BOOTSTRAP_CHECKPOINT_REQUIRED_BITMAPS: [u64; 6] =
    [0, 0b00_0001, 0b00_0011, 0b00_0011, 0b00_1011, 0b01_1011];
const BOOTSTRAP_FOLLOWUP_CHECKPOINT_NAMES: [&str; 6] = [
    "feeder-scheduler-selected",
    "main-bootstrap-returned",
    "serial-init-entered",
    "serial-init-returned",
    "rtc-output-entered",
    "rtc-output-returned",
];
const BOOTSTRAP_FOLLOWUP_REQUIRED_BOOTSTRAP_BITMAPS: [u64; 6] = [
    0b00_0010, 0b00_0100, 0b00_0100, 0b00_0100, 0b00_0100, 0b00_0100,
];
const BOOTSTRAP_FOLLOWUP_REQUIRED_BITMAPS: [u64; 6] =
    [0, 0, 0b00_0010, 0b00_0110, 0b00_1110, 0b01_1110];
const WATCHDOG_MARKER_PREFIX: &str = "STARRY_KERNEL_WATCHDOG version=1 state=armed ";
const GUEST_START_MARKER_PREFIX: &str = "KERNDIFF_GUEST_START version=1 run_id=";
pub(crate) const BOOT_PROBE_SUCCESS_REGEX: &str =
    r"(?m)^KERNDIFF_GUEST_START version=1 run_id=[0-9a-f]+\r?$";
const WATCHDOG_PMEMSAVE_REQUEST_ID: &str = "kerndiff-watchdog-pmemsave";
static SOCKET_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static DIAGNOSTIC_PAGE_PA: AtomicU64 = AtomicU64::new(0);
static GUEST_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub(crate) struct QemuFaultPaths {
    socket: PathBuf,
}

impl QemuFaultPaths {
    pub(crate) fn new(workspace: &Path) -> anyhow::Result<Self> {
        DIAGNOSTIC_PAGE_PA.store(0, Ordering::Release);
        GUEST_STARTED.store(false, Ordering::Release);
        let root = workspace.join("tmp/axbuild/qmp");
        fs::create_dir_all(&root)?;
        let sequence = SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            socket: root.join(format!("kerndiff-{}-{sequence}.sock", std::process::id())),
        })
    }
}

#[derive(Default)]
pub(crate) struct GuestOutputObserver {
    line_buf: Vec<u8>,
}

impl GuestOutputObserver {
    pub(crate) fn append(&mut self, chunk: &[u8]) {
        self.line_buf.extend_from_slice(chunk);
        while let Some(newline) = self.line_buf.iter().position(|byte| *byte == b'\n') {
            let line = String::from_utf8_lossy(&self.line_buf[..newline]);
            observe_guest_output_line(line.trim_end_matches('\r'));
            self.line_buf.drain(..=newline);
        }
        if self.line_buf.len() > MAX_GUEST_OUTPUT_LINE_BYTES {
            let overflow = self.line_buf.len() - MAX_GUEST_OUTPUT_LINE_BYTES;
            self.line_buf.drain(..overflow);
        }
    }
}

fn observe_guest_output_line(line: &str) {
    let normalized = line.trim_start_matches(['\u{1b}', '[']);
    if is_guest_start_marker(normalized) {
        GUEST_STARTED.store(true, Ordering::Release);
    }
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

fn is_guest_start_marker(line: &str) -> bool {
    let Some(prefix) = line.find(GUEST_START_MARKER_PREFIX) else {
        return false;
    };
    let run_id = &line[prefix + GUEST_START_MARKER_PREFIX.len()..];
    !run_id.is_empty()
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn enabled() -> bool {
    std::env::var("KERNDIFF_QMP_FAULTS")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "y" | "yes" | "true" | "on"))
}

pub(crate) fn boot_probe_enabled() -> bool {
    std::env::var("KERNDIFF_BOOT_PROBE")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "y" | "yes" | "true" | "on"))
}

#[cfg(test)]
pub(crate) fn reset_guest_started_for_test() {
    GUEST_STARTED.store(false, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn guest_started_for_test() -> bool {
    GUEST_STARTED.load(Ordering::Acquire)
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
        if should_quit_boot_probe(boot_probe_enabled(), GUEST_STARTED.load(Ordering::Acquire)) {
            write_qmp_command(&mut stream, "quit")?;
            break;
        }
        let value = match read_qmp_message_once(&mut reader) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
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

const fn should_quit_boot_probe(enabled: bool, guest_started: bool) -> bool {
    enabled && guest_started
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

fn read_qmp_message_once(
    reader: &mut BufReader<UnixStream>,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => bail!("QMP socket closed"),
        Ok(_) => serde_json::from_str(line.trim_end())
            .context("QMP emitted invalid JSON")
            .map(Some),
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
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
    let declared_size = usize::try_from(size).unwrap_or(usize::MAX);
    let minimum_size = match version {
        DIAGNOSTIC_VERSION_V1 => V1_DIAGNOSTIC_BYTES,
        DIAGNOSTIC_VERSION_V2 => V2_DIAGNOSTIC_BYTES,
        DIAGNOSTIC_VERSION_V3 => V3_DIAGNOSTIC_BYTES,
        DIAGNOSTIC_VERSION_V4 => V4_DIAGNOSTIC_BYTES,
        _ => usize::MAX,
    };
    if magic != DIAGNOSTIC_MAGIC
        || declared_size < minimum_size
        || declared_size > DIAGNOSTIC_PAGE_BYTES
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
    let mut diagnostic = serde_json::json!({
        "schema_name": "starry-kernel-watchdog-diagnostic",
        "schema_version": version,
        "boot_epoch": boot_epoch,
        "online_cpu_mask": format!("{online_mask:#x}"),
        "stuck_cpu_mask": format!("{stale_mask:#x}"),
        "cpus": cpus,
    });
    if matches!(
        version,
        DIAGNOSTIC_VERSION_V2 | DIAGNOSTIC_VERSION_V3 | DIAGNOSTIC_VERSION_V4
    ) {
        let reached = read_u64(encoded, V1_DIAGNOSTIC_BYTES)?;
        let last_phase = read_u32(encoded, V1_DIAGNOSTIC_BYTES + 8)?;
        let sequence = read_u64(encoded, V1_DIAGNOSTIC_BYTES + 16)?;
        validate_boot_phases(reached, last_phase, sequence)?;
        let mut elapsed = serde_json::Map::new();
        for (phase, name) in BOOT_PHASE_NAMES.iter().enumerate() {
            if reached & (1u64 << phase) != 0 {
                elapsed.insert(
                    (*name).to_string(),
                    read_u64(encoded, V1_DIAGNOSTIC_BYTES + 24 + phase * 8)?.into(),
                );
            }
        }
        let object = diagnostic
            .as_object_mut()
            .expect("diagnostic JSON must be an object");
        object.insert(
            "reached_phase_bitmap".to_string(),
            format!("{reached:#x}").into(),
        );
        object.insert("phase_sequence".to_string(), sequence.into());
        object.insert("phase_elapsed_ns".to_string(), elapsed.into());
        object.insert(
            "last_phase".to_string(),
            if sequence == 0 {
                serde_json::Value::Null
            } else {
                BOOT_PHASE_NAMES[last_phase as usize].into()
            },
        );
    }
    let mut bootstrap_checkpoints = 0;
    if matches!(version, DIAGNOSTIC_VERSION_V3 | DIAGNOSTIC_VERSION_V4) {
        let reached = read_u64(encoded, V2_DIAGNOSTIC_BYTES)?;
        bootstrap_checkpoints = reached;
        validate_bootstrap_checkpoints(reached)?;
        let mut elapsed = serde_json::Map::new();
        for (checkpoint, name) in BOOTSTRAP_CHECKPOINT_NAMES.iter().enumerate() {
            if reached & (1u64 << checkpoint) != 0 {
                elapsed.insert(
                    (*name).to_string(),
                    read_u64(encoded, V2_DIAGNOSTIC_BYTES + 8 + checkpoint * 8)?.into(),
                );
            }
        }
        let object = diagnostic
            .as_object_mut()
            .expect("diagnostic JSON must be an object");
        object.insert(
            "bootstrap_checkpoint_bitmap".to_string(),
            format!("{reached:#x}").into(),
        );
        object.insert(
            "bootstrap_checkpoint_elapsed_ns".to_string(),
            elapsed.into(),
        );
    }
    if version == DIAGNOSTIC_VERSION_V4 {
        let reached = read_u64(encoded, V3_DIAGNOSTIC_BYTES)?;
        validate_bootstrap_followup_checkpoints(bootstrap_checkpoints, reached)?;
        let mut elapsed = serde_json::Map::new();
        for (checkpoint, name) in BOOTSTRAP_FOLLOWUP_CHECKPOINT_NAMES.iter().enumerate() {
            if reached & (1u64 << checkpoint) != 0 {
                elapsed.insert(
                    (*name).to_string(),
                    read_u64(encoded, V3_DIAGNOSTIC_BYTES + 8 + checkpoint * 8)?.into(),
                );
            }
        }
        let object = diagnostic
            .as_object_mut()
            .expect("diagnostic JSON must be an object");
        object.insert(
            "bootstrap_followup_checkpoint_bitmap".to_string(),
            format!("{reached:#x}").into(),
        );
        object.insert(
            "bootstrap_followup_checkpoint_elapsed_ns".to_string(),
            elapsed.into(),
        );
    }
    Ok(diagnostic)
}

fn validate_boot_phases(reached: u64, last_phase: u32, sequence: u64) -> anyhow::Result<()> {
    if sequence > BOOT_PHASE_NAMES.len() as u64 {
        bail!("watchdog diagnostic phase sequence is invalid: {sequence}")
    }
    let expected_bitmap = if sequence == 0 {
        0
    } else {
        (1u64 << sequence) - 1
    };
    let expected_last = if sequence == 0 {
        u32::MAX
    } else {
        u32::try_from(sequence - 1).unwrap()
    };
    if reached != expected_bitmap || last_phase != expected_last {
        bail!(
            "watchdog diagnostic phase prefix is invalid: bitmap={reached:#x} \
             last_phase={last_phase} sequence={sequence}"
        )
    }
    Ok(())
}

fn validate_bootstrap_checkpoints(reached: u64) -> anyhow::Result<()> {
    let valid_bitmap = (1u64 << BOOTSTRAP_CHECKPOINT_NAMES.len()) - 1;
    if reached & !valid_bitmap != 0 {
        bail!("watchdog diagnostic bootstrap checkpoint bitmap is invalid: {reached:#x}")
    }
    for (checkpoint, required) in BOOTSTRAP_CHECKPOINT_REQUIRED_BITMAPS
        .iter()
        .copied()
        .enumerate()
    {
        let bit = 1u64 << checkpoint;
        if reached & bit != 0 && reached & required != required {
            bail!(
                "watchdog diagnostic bootstrap checkpoint dependencies are invalid: \
                 bitmap={reached:#x} checkpoint={}",
                BOOTSTRAP_CHECKPOINT_NAMES[checkpoint]
            )
        }
    }
    Ok(())
}

fn validate_bootstrap_followup_checkpoints(bootstrap: u64, reached: u64) -> anyhow::Result<()> {
    let valid_bitmap = (1u64 << BOOTSTRAP_FOLLOWUP_CHECKPOINT_NAMES.len()) - 1;
    if reached & !valid_bitmap != 0 {
        bail!("watchdog diagnostic bootstrap follow-up bitmap is invalid: {reached:#x}")
    }
    for checkpoint in 0..BOOTSTRAP_FOLLOWUP_CHECKPOINT_NAMES.len() {
        let bit = 1u64 << checkpoint;
        if reached & bit == 0 {
            continue;
        }
        let required_bootstrap = BOOTSTRAP_FOLLOWUP_REQUIRED_BOOTSTRAP_BITMAPS[checkpoint];
        let required_followup = BOOTSTRAP_FOLLOWUP_REQUIRED_BITMAPS[checkpoint];
        if bootstrap & required_bootstrap != required_bootstrap
            || reached & required_followup != required_followup
        {
            bail!(
                "watchdog diagnostic bootstrap follow-up dependencies are invalid: \
                 bootstrap={bootstrap:#x} followup={reached:#x} checkpoint={}",
                BOOTSTRAP_FOLLOWUP_CHECKPOINT_NAMES[checkpoint]
            )
        }
    }
    Ok(())
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

        let mut page = diagnostic_page(DIAGNOSTIC_VERSION_V1);
        page[8..12].copy_from_slice(&(1576u32).to_le_bytes());
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

    #[test]
    fn decodes_v2_phase_prefix_and_rejects_gaps() {
        let mut page = diagnostic_page(DIAGNOSTIC_VERSION_V2);
        page[V1_DIAGNOSTIC_BYTES..V1_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b111u64).to_le_bytes());
        page[V1_DIAGNOSTIC_BYTES + 8..V1_DIAGNOSTIC_BYTES + 12]
            .copy_from_slice(&(2u32).to_le_bytes());
        page[V1_DIAGNOSTIC_BYTES + 16..V1_DIAGNOSTIC_BYTES + 24]
            .copy_from_slice(&(3u64).to_le_bytes());
        page[V1_DIAGNOSTIC_BYTES + 24..V1_DIAGNOSTIC_BYTES + 32]
            .copy_from_slice(&(10u64).to_le_bytes());
        page[V1_DIAGNOSTIC_BYTES + 40..V1_DIAGNOSTIC_BYTES + 48]
            .copy_from_slice(&(30u64).to_le_bytes());

        let diagnostic = decode_diagnostic_page(&page).unwrap();
        assert_eq!(diagnostic["schema_version"], 2);
        assert_eq!(diagnostic["last_phase"], "filesystem-init-ready");
        assert_eq!(diagnostic["phase_sequence"], 3);
        assert_eq!(diagnostic["phase_elapsed_ns"]["watchdog-armed"], 10);
        assert_eq!(diagnostic["phase_elapsed_ns"]["filesystem-init-ready"], 30);

        page[V1_DIAGNOSTIC_BYTES..V1_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b101u64).to_le_bytes());
        assert!(decode_diagnostic_page(&page).is_err());
    }

    #[test]
    fn decodes_v3_bootstrap_checkpoints_and_rejects_broken_dependencies() {
        let mut page = diagnostic_page(DIAGNOSTIC_VERSION_V3);
        page[V1_DIAGNOSTIC_BYTES + 8..V1_DIAGNOSTIC_BYTES + 12]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        page[V2_DIAGNOSTIC_BYTES..V2_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b11_1111u64).to_le_bytes());
        for (checkpoint, elapsed_ns) in [101u64, 202, 303, 404, 505, 606].into_iter().enumerate() {
            let offset = V2_DIAGNOSTIC_BYTES + 8 + checkpoint * 8;
            page[offset..offset + 8].copy_from_slice(&elapsed_ns.to_le_bytes());
        }

        let diagnostic = decode_diagnostic_page(&page).unwrap();
        assert_eq!(diagnostic["schema_version"], 3);
        assert_eq!(diagnostic["bootstrap_checkpoint_bitmap"], "0x3f");
        assert_eq!(
            diagnostic["bootstrap_checkpoint_elapsed_ns"]["feeder-spawn-requested"],
            101
        );
        assert_eq!(
            diagnostic["bootstrap_checkpoint_elapsed_ns"]["feeder-first-poll-complete"],
            606
        );
        assert!(
            diagnostic
                .get("bootstrap_followup_checkpoint_bitmap")
                .is_none()
        );

        page[V2_DIAGNOSTIC_BYTES..V2_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b00_1001u64).to_le_bytes());
        assert!(decode_diagnostic_page(&page).is_err());
    }

    #[test]
    fn decodes_v4_post_spawn_checkpoints_and_rejects_broken_dependencies() {
        let mut page = diagnostic_page(DIAGNOSTIC_VERSION_V4);
        page[V1_DIAGNOSTIC_BYTES + 8..V1_DIAGNOSTIC_BYTES + 12]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        page[V2_DIAGNOSTIC_BYTES..V2_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b00_0111u64).to_le_bytes());
        page[V3_DIAGNOSTIC_BYTES..V3_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b11_1111u64).to_le_bytes());
        for (checkpoint, elapsed_ns) in [701u64, 702, 703, 704, 705, 706].into_iter().enumerate() {
            let offset = V3_DIAGNOSTIC_BYTES + 8 + checkpoint * 8;
            page[offset..offset + 8].copy_from_slice(&elapsed_ns.to_le_bytes());
        }

        let diagnostic = decode_diagnostic_page(&page).unwrap();
        assert_eq!(diagnostic["schema_version"], 4);
        assert_eq!(diagnostic["bootstrap_followup_checkpoint_bitmap"], "0x3f");
        assert_eq!(
            diagnostic["bootstrap_followup_checkpoint_elapsed_ns"]["feeder-scheduler-selected"],
            701
        );
        assert_eq!(
            diagnostic["bootstrap_followup_checkpoint_elapsed_ns"]["rtc-output-returned"],
            706
        );

        page[V3_DIAGNOSTIC_BYTES..V3_DIAGNOSTIC_BYTES + 8]
            .copy_from_slice(&(0b10_0100u64).to_le_bytes());
        assert!(decode_diagnostic_page(&page).is_err());
    }

    #[test]
    fn guest_start_enables_only_an_explicit_boot_probe_quit() {
        GUEST_STARTED.store(false, Ordering::Release);
        observe_guest_output_line("KERNDIFF_GUEST_START version=1 run_id=not-hex");
        assert!(!GUEST_STARTED.load(Ordering::Acquire));
        observe_guest_output_line("KERNDIFF_GUEST_START version=1 run_id=abc123");
        assert!(GUEST_STARTED.load(Ordering::Acquire));
        assert!(should_quit_boot_probe(true, true));
        assert!(!should_quit_boot_probe(false, true));
        assert!(!should_quit_boot_probe(true, false));
    }

    fn diagnostic_page(version: u32) -> Vec<u8> {
        let mut page = vec![0u8; DIAGNOSTIC_PAGE_BYTES];
        page[0..4].copy_from_slice(&DIAGNOSTIC_MAGIC.to_le_bytes());
        page[4..8].copy_from_slice(&version.to_le_bytes());
        page[8..12].copy_from_slice(&(DIAGNOSTIC_PAGE_BYTES as u32).to_le_bytes());
        page[12..16].copy_from_slice(&(MAX_DIAGNOSTIC_CPUS as u32).to_le_bytes());
        page
    }
}
