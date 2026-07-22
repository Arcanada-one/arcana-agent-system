//! Offline test fixture for the supervisor chaos/watchdog tests.
//!
//! Emits a stdout heartbeat line-protocol (`READY`, `HEARTBEAT <seq>`,
//! `STATUS ...`), each line **flushed** because a piped stdout is block-buffered
//! and the supervisor would otherwise never observe a heartbeat. Fully offline:
//! no network, no ecosystem services. Flags:
//!
//! - `--interval <ms>`: heartbeat interval (default 50).
//! - `--heartbeats <n>`: emit `n` heartbeats then exit (default: forever).
//! - `--exit-code <n>`: exit code when `--heartbeats` is reached (default 0).
//! - `--stop-heartbeat-after <ms>`: keep running but stop emitting after `ms`.
//! - `--ignore-term`: block `SIGTERM` via safe `sigprocmask` (never an `unsafe`
//!   disposition install) so the child survives `SIGTERM` and dies only on
//!   `SIGKILL`.
//! - `--spawn-grandchild`: fork a `sleep 3600` into this process group and print
//!   `STATUS grandchild=<pid>`.

#![cfg(unix)]

use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::sys::signal::{sigprocmask, SigSet, SigmaskHow, Signal};

struct Options {
    interval: Duration,
    heartbeats: Option<u64>,
    exit_code: i32,
    stop_after: Option<Duration>,
    ignore_term: bool,
    spawn_grandchild: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("heartbeat-child: {err}");
        std::process::exit(70);
    }
}

fn run() -> io::Result<()> {
    let opts = parse_options();

    if opts.ignore_term {
        block_sigterm().map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    emit(&mut out, "READY")?;

    if opts.spawn_grandchild {
        // A grandchild that stays in *this* process group and also blocks
        // `SIGTERM` (a fresh `heartbeat-child --ignore-term`, silent). It can
        // therefore be reaped ONLY by the group `SIGKILL` escalation — not by
        // `SIGTERM`, and not by the parent's tokio `kill_on_drop`, which reaps
        // the direct-child pid alone. A group-level `ESRCH` probe against such a
        // grandchild isolates the budgeted group SIGKILL (V-AC-2 / V-AC-9).
        let exe = std::env::current_exe()?;
        let grandchild = Command::new(exe)
            .arg("--ignore-term")
            .arg("--stop-heartbeat-after")
            .arg("0")
            .arg("--interval")
            .arg("3600000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        emit(&mut out, &format!("STATUS grandchild={}", grandchild.id()))?;
    }

    let start = Instant::now();
    let mut seq = 0u64;
    loop {
        let silent = opts
            .stop_after
            .is_some_and(|limit| start.elapsed() >= limit);
        if !silent {
            // Best-effort: a closed reader pipe (EPIPE) must NOT kill the child.
            // Terminability is exercised via signals only, so a `--ignore-term`
            // child truly survives SIGTERM and forces the SIGKILL escalation.
            if emit(&mut out, &format!("HEARTBEAT {seq}")).is_ok() {
                seq += 1;
                if let Some(limit) = opts.heartbeats {
                    if seq >= limit {
                        std::process::exit(opts.exit_code);
                    }
                }
            }
        }
        sleep(opts.interval);
    }
}

fn emit(out: &mut impl Write, line: &str) -> io::Result<()> {
    writeln!(out, "{line}")?;
    out.flush()
}

fn block_sigterm() -> Result<(), nix::errno::Errno> {
    let mut set = SigSet::empty();
    set.add(Signal::SIGTERM);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), None)
}

fn parse_options() -> Options {
    let mut opts = Options {
        interval: Duration::from_millis(50),
        heartbeats: None,
        exit_code: 0,
        stop_after: None,
        ignore_term: false,
        spawn_grandchild: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--interval" => opts.interval = Duration::from_millis(next_u64(&mut args)),
            "--heartbeats" => opts.heartbeats = Some(next_u64(&mut args)),
            "--exit-code" => opts.exit_code = next_i32(&mut args),
            "--stop-heartbeat-after" => {
                opts.stop_after = Some(Duration::from_millis(next_u64(&mut args)));
            }
            "--ignore-term" => opts.ignore_term = true,
            "--spawn-grandchild" => opts.spawn_grandchild = true,
            _ => {}
        }
    }
    opts
}

fn next_u64(args: &mut impl Iterator<Item = String>) -> u64 {
    args.next().and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn next_i32(args: &mut impl Iterator<Item = String>) -> i32 {
    args.next().and_then(|v| v.parse().ok()).unwrap_or(0)
}
