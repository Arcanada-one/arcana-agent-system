//! Stdout that survives a closed reader.
//!
//! Rust sets `SIGPIPE` to `SIG_IGN` at startup, so a reader going away surfaces
//! as an `EPIPE` write error rather than terminating the process — and
//! `println!` turns that error into a **panic**, which exits 101 with the panic
//! message itself lost to the same closed pipe. The user sees a plausible-looking
//! prefix of the output and a failure code with no explanation.
//!
//! `arcana models` prints 123 lines against the production catalogue, so `| head`,
//! `| grep` and `| less` with an early quit are the normal ways to read it. Any of
//! them yielded exit 101 and broke `set -o pipefail` scripts.
//!
//! The usual fix is `libc::signal(SIGPIPE, SIG_DFL)`, which this workspace cannot
//! use: `unsafe_code = "forbid"` at the workspace root, and `forbid` cannot be
//! locally overridden. So the pipe is handled where it breaks instead — write
//! through a checked handle and treat `BrokenPipe` as the reader having finished,
//! which it has.

use std::io::{self, ErrorKind, Write};

/// Write `text` to stdout, tolerating a reader that has gone away.
///
/// # Returns
/// The process exit code: `0` when written in full, `0` when the reader closed
/// the pipe (that is not a failure of this command), and `1` for any other I/O
/// error, which is reported on stderr.
#[must_use]
pub fn write_all(text: &str) -> i32 {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match handle
        .write_all(text.as_bytes())
        .and_then(|()| handle.flush())
    {
        Ok(()) => 0,
        // `head -n 5` closing after five lines is the reader saying "enough",
        // not an error in producing them.
        Err(error) if error.kind() == ErrorKind::BrokenPipe => 0,
        Err(error) => {
            eprintln!("arcana: could not write output: {error}");
            1
        }
    }
}

/// Whether an I/O error means the reader closed the pipe.
///
/// Exposed so callers streaming incrementally can make the same judgement
/// without duplicating the match.
#[must_use]
pub fn is_closed_reader(error: &io::Error) -> bool {
    error.kind() == ErrorKind::BrokenPipe
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::is_closed_reader;
    use std::io::{Error, ErrorKind};

    #[test]
    fn a_closed_reader_is_recognised() {
        assert!(is_closed_reader(&Error::new(
            ErrorKind::BrokenPipe,
            "epipe"
        )));
    }

    #[test]
    fn other_io_errors_are_not_treated_as_a_closed_reader() {
        // A full disk or a permissions failure must still be a failure; folding
        // every write error into "the reader left" would hide real ones.
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::StorageFull,
            ErrorKind::WriteZero,
        ] {
            assert!(!is_closed_reader(&Error::new(kind, "x")), "{kind:?}");
        }
    }
}
