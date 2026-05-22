use log::{info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bpf_loader::BpfJailerBpf;

const PERF_PAGES: usize = 8;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: u32 = 10;
const POLL_TIMEOUT: Duration = Duration::from_millis(100);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AuditEvent {
    timestamp: u64,
    pid: u32,
    role_id: u32,
    decision: u32,
    hook_type: u32,
    context: u64,
    pod_id: u64,
}

fn hook_name(hook_type: u32) -> &'static str {
    match hook_type {
        1 => "file_open",
        2 => "socket_bind",
        3 => "socket_connect",
        4 => "bprm_check",
        5 => "path_rename",
        _ => "unknown",
    }
}

fn decision_name(decision: u32) -> &'static str {
    match decision {
        0 => "deny",
        1 => "allow",
        _ => "unknown",
    }
}

/// Rate limiter keyed by (role_id, hook_type, context).
struct RateLimiter {
    buckets: HashMap<(u32, u32, u64), (u32, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { buckets: HashMap::new() }
    }

    /// Returns true if the event should be emitted (not rate-limited).
    fn allow(&mut self, role_id: u32, hook_type: u32, context: u64) -> bool {
        let key = (role_id, hook_type, context);
        let now = Instant::now();
        let entry = self.buckets.entry(key).or_insert((0, now));
        if now.duration_since(entry.1) >= RATE_LIMIT_WINDOW {
            *entry = (1, now);
            return true;
        }
        entry.0 += 1;
        entry.0 <= RATE_LIMIT_MAX
    }

    /// Periodic cleanup of expired entries to prevent unbounded growth.
    fn gc(&mut self) {
        let now = Instant::now();
        self.buckets.retain(|_, (_, t)| now.duration_since(*t) < RATE_LIMIT_WINDOW);
    }
}

/// Start the audit reader thread. Polls the BPF perf buffer and logs events.
/// This spawns a dedicated OS thread (not a tokio task) because
/// PerfBuffer::poll() is blocking.
pub fn start_audit_thread(bpf: Arc<BpfJailerBpf>) {
    std::thread::Builder::new()
        .name("audit-reader".into())
        .spawn(move || {
            if let Err(e) = run_audit_loop(&bpf) {
                log::error!("audit thread exited with error: {}", e);
            }
        })
        .expect("failed to spawn audit thread");

    info!("Audit perf buffer reader started");
}

fn run_audit_loop(bpf: &BpfJailerBpf) -> anyhow::Result<()> {
    let mut limiter = RateLimiter::new();
    let mut gc_counter: u32 = 0;

    let pb = bpf.build_audit_perf_buffer(
        move |_cpu: i32, data: &[u8]| {
            if data.len() < std::mem::size_of::<AuditEvent>() {
                return;
            }
            let event: AuditEvent = unsafe {
                std::ptr::read_unaligned(data.as_ptr() as *const AuditEvent)
            };

            if !limiter.allow(event.role_id, event.hook_type, event.context) {
                return;
            }

            // Log as structured key=value for easy parsing by log aggregators.
            // When journald integration is added, these become journal fields.
            info!(
                target: "icb_sandbox_audit",
                "pid={} role_id={} pod_id={} decision={} hook={} context=0x{:x}",
                event.pid,
                event.role_id,
                event.pod_id,
                decision_name(event.decision),
                hook_name(event.hook_type),
                event.context,
            );

            gc_counter += 1;
            if gc_counter % 1000 == 0 {
                limiter.gc();
            }
        },
        PERF_PAGES,
    )?;

    info!("Audit perf buffer attached, polling...");

    loop {
        match pb.poll(POLL_TIMEOUT) {
            Ok(()) => {}
            Err(e) => {
                warn!("audit perf buffer poll error: {} (retrying)", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
