//! Size-rotated log files.
//!
//! The agent writes its `tracing` log to `agent.log` in the log directory
//! (`%ProgramData%\Palisade\logs` by default, created and ACLed by the
//! installer). When a write would take the file past the size limit, the
//! files are shifted: `agent.log.(n-2)` becomes `agent.log.(n-1)`, and so on,
//! `agent.log` becomes `agent.log.1`, and a new `agent.log` is started. With
//! the default of 10 files of 10 MiB, the log takes at most 100 MiB.
//!
//! The formatter hands each record to the writer in one `write`, so a
//! record is never split across two files. A record larger than the limit
//! is written to a file of its own.
//!
//! Logging must never stop the agent: a failed rotation or write is
//! reported once to standard error and the record is dropped.

#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

/// The name of the current log file.
pub const FILE_NAME: &str = "agent.log";

/// A log file that rotates by size.
#[derive(Debug)]
pub struct RotatingFile {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    dir: PathBuf,
    max_bytes: u64,
    files: usize,
    file: Option<File>,
    size: u64,
    /// Whether a failure has been reported since the last success.
    reported: bool,
}

impl RotatingFile {
    /// Opens (appending to) `dir/agent.log`, keeping `files` files of at
    /// most `max_bytes` each. `files` and `max_bytes` below 1 are raised
    /// to 1. The directory must exist: creating it, with its ACL, is the
    /// installer's job.
    pub fn open(dir: &Path, files: usize, max_bytes: u64) -> io::Result<Self> {
        let (file, size) = open_current(dir)?;
        Ok(Self {
            state: Mutex::new(State {
                dir: dir.to_path_buf(),
                max_bytes: max_bytes.max(1),
                files: files.max(1),
                file: Some(file),
                size,
                reported: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The path of the `index`th file: 0 is `agent.log`, then
    /// `agent.log.1` and so on.
    pub fn path(dir: &Path, index: usize) -> PathBuf {
        if index == 0 {
            dir.join(FILE_NAME)
        } else {
            dir.join(format!("{FILE_NAME}.{index}"))
        }
    }
}

fn open_current(dir: &Path) -> io::Result<(File, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(RotatingFile::path(dir, 0))?;
    let size = file.metadata()?.len();
    Ok((file, size))
}

impl State {
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        let last = self.files - 1;
        if last == 0 {
            // A single file: start it again.
            match fs::remove_file(RotatingFile::path(&self.dir, 0)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        } else {
            for index in (0..last).rev() {
                let from = RotatingFile::path(&self.dir, index);
                // `rename` replaces the target on every supported OS.
                match fs::rename(&from, RotatingFile::path(&self.dir, index + 1)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let (file, size) = open_current(&self.dir)?;
        self.file = Some(file);
        self.size = size;
        Ok(())
    }

    fn write_record(&mut self, buf: &[u8]) -> io::Result<()> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.file.is_none() || (self.size > 0 && self.size.saturating_add(len) > self.max_bytes)
        {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file is not open"))?;
        file.write_all(buf)?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }
}

impl Write for &RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.lock();
        match state.write_record(buf) {
            Ok(()) => state.reported = false,
            Err(e) => {
                if !state.reported {
                    state.reported = true;
                    let _ = writeln!(
                        io::stderr(),
                        "palisade-agent: cannot write the log file in {}: {e}",
                        state.dir.display()
                    );
                }
            }
        }
        // The record is consumed either way: a failing log never fails the
        // caller.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.lock().file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingFile {
    type Writer = &'a RotatingFile;

    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "palisade-agent-logfile-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn read(&self, index: usize) -> Option<String> {
            fs::read_to_string(RotatingFile::path(&self.0, index)).ok()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(log: &RotatingFile, text: &str) {
        let mut w: &RotatingFile = log;
        assert_eq!(w.write(text.as_bytes()).unwrap(), text.len());
    }

    #[test]
    fn records_rotate_by_size_and_old_files_are_dropped() {
        let dir = TempDir::new("rotate");
        let log = RotatingFile::open(&dir.0, 3, 10).unwrap();
        for record in [
            "aaaa\n", "bbbb\n", "cccc\n", "dddd\n", "eeee\n", "ffff\n", "gggg\n",
        ] {
            write(&log, record);
        }
        (&log).flush().unwrap();
        assert_eq!(dir.read(0).as_deref(), Some("gggg\n"));
        assert_eq!(dir.read(1).as_deref(), Some("eeee\nffff\n"));
        assert_eq!(dir.read(2).as_deref(), Some("cccc\ndddd\n"));
        assert_eq!(dir.read(3), None);
    }

    #[test]
    fn a_large_record_gets_a_file_of_its_own() {
        let dir = TempDir::new("large");
        let log = RotatingFile::open(&dir.0, 2, 4).unwrap();
        write(&log, "0123456789\n");
        write(&log, "x\n");
        assert_eq!(dir.read(0).as_deref(), Some("x\n"));
        assert_eq!(dir.read(1).as_deref(), Some("0123456789\n"));
    }

    #[test]
    fn reopening_appends_and_counts_the_existing_size() {
        let dir = TempDir::new("reopen");
        fs::write(RotatingFile::path(&dir.0, 0), "old\n").unwrap();
        let log = RotatingFile::open(&dir.0, 2, 8).unwrap();
        write(&log, "new\n");
        assert_eq!(dir.read(0).as_deref(), Some("old\nnew\n"));
        write(&log, "next\n");
        assert_eq!(dir.read(1).as_deref(), Some("old\nnew\n"));
        assert_eq!(dir.read(0).as_deref(), Some("next\n"));
    }

    #[test]
    fn one_file_restarts_and_zero_limits_are_raised() {
        let dir = TempDir::new("single");
        let log = RotatingFile::open(&dir.0, 0, 0).unwrap();
        write(&log, "one\n");
        write(&log, "two\n");
        assert_eq!(dir.read(0).as_deref(), Some("two\n"));
        assert_eq!(dir.read(1), None);
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let dir = TempDir::new("absent");
        assert!(RotatingFile::open(&dir.0.join("absent"), 2, 8).is_err());
    }

    /// Windows does not remove a directory while a file in it is open, so
    /// the failure is provoked on Unix only.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_is_swallowed_and_retried() {
        let dir = TempDir::new("missing");
        let log = RotatingFile::open(&dir.0, 2, 4).unwrap();
        // The directory goes away: rotation fails, the write still
        // "succeeds", and the next one is attempted again.
        fs::remove_dir_all(&dir.0).unwrap();
        write(&log, "lost record\n");
        write(&log, "lost again\n");
        assert!(log.lock().reported);
        (&log).flush().unwrap();
        fs::create_dir_all(&dir.0).unwrap();
        write(&log, "back\n");
        assert!(!log.lock().reported);
        assert_eq!(dir.read(0).as_deref(), Some("back\n"));
    }
}
