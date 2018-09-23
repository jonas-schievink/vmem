//! Provides signal-safe functionality.

use imp;

use std::fmt;

/// Writes to the standard output.
///
/// Errors are ignored.
pub fn write_stdout<T: AsRef<[u8]>>(data: T) {
    imp::write_stdout(data.as_ref()).ok();  // ignore errors
}

/// Writes to the standard error stream.
///
/// Errors are ignored.
pub fn write_stderr<T: AsRef<[u8]>>(data: T) {
    imp::write_stderr(data.as_ref()).ok();  // ignore errors
}

/// The standard output stream.
///
/// Implements `fmt::Write`.
#[derive(Debug)]
pub struct Stdout {}

impl Stdout {
    /// Creates a new handle to the standard output stream.
    ///
    /// This won't open a new file, so the stream also will not be closed upon
    /// drop.
    pub fn new() -> Self {
        Self {}
    }
}

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = s.as_bytes();
        while !buf.is_empty() {
            match imp::write_stdout(buf) {
                Ok(0) => return Err(fmt::Error),
                Ok(n) => buf = &buf[n..],
                Err(()) => return Err(fmt::Error),
            }
        }
        Ok(())
    }
}

// Can't really implement `io::Write` because `io::Error` doesn't guarantee that it won't allocate
