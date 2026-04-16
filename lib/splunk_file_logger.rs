#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
use rand::Rng;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError, bounded};

pub struct FileLogger {
    inner: Arc<FileLoggerInner>,
    session_id: Arc<AtomicU64>,
}

struct FileLoggerInner {
    command_tx: Sender<Command>,
    join: Mutex<Option<JoinHandle<FileLoggerStats>>>,
    shutdown: AtomicBool,
    final_stats: Mutex<Option<FileLoggerStats>>,
}

#[derive(Clone, Debug)]
pub struct FileLoggerConfig {
    base_path: PathBuf,
    pub buffer_size: usize,
    pub rotate_size_bytes: Option<u64>,
    pub max_rotate_files: usize,
    pub ensure_newline: bool,
    pub sync_on_flush: bool,
    pub auto_flush_interval: Option<Duration>,
    pub queue_capacity: Option<usize>,
    pub session_id: Option<u64>,
}

impl FileLoggerConfig {
    pub fn new<P: Into<PathBuf>>(base_path: P) -> Self {
        Self {
            base_path: base_path.into(),
            buffer_size: 8 * 1024,
            rotate_size_bytes: None,
            max_rotate_files: 0,
            ensure_newline: true,
            sync_on_flush: false,
            auto_flush_interval: None,
            queue_capacity: Some(1024),
            session_id: None,
        }
    }

    pub fn base_path(&self) -> PathBuf {
        self.base_path.clone()
    }

    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size.max(1);
        self
    }

    pub fn with_rotate_size_bytes(mut self, rotate_size_bytes: Option<u64>) -> Self {
        self.rotate_size_bytes = rotate_size_bytes;
        self
    }

    pub fn with_max_rotate_files(mut self, max_rotate_files: usize) -> Self {
        self.max_rotate_files = max_rotate_files;
        self
    }

    pub fn with_ensure_newline(mut self, ensure_newline: bool) -> Self {
        self.ensure_newline = ensure_newline;
        self
    }

    pub fn with_sync_on_flush(mut self, sync_on_flush: bool) -> Self {
        self.sync_on_flush = sync_on_flush;
        self
    }

    pub fn with_auto_flush_interval(mut self, interval: Option<Duration>) -> Self {
        self.auto_flush_interval = interval;
        self
    }

    pub fn with_queue_capacity(mut self, capacity: Option<usize>) -> Self {
        self.queue_capacity = capacity;
        self
    }

    pub fn with_session_id(mut self, session_id: Option<u64>) -> Self {
        self.session_id = session_id;
        self
    }
}

#[derive(Clone, Debug)]
pub struct FileLoggerStats {
    pub bytes_written: u64,
    pub records_written: u64,
    pub flush_count: u64,
    pub rotate_count: u64,
    pub uptime: Duration,
    pub started_at: SystemTime,
    pub last_flush_at: Option<SystemTime>,
    pub last_error: Option<String>,
}

impl FileLoggerStats {
    fn new_started() -> Self {
        Self {
            bytes_written: 0,
            records_written: 0,
            flush_count: 0,
            rotate_count: 0,
            uptime: Duration::ZERO,
            started_at: SystemTime::now(),
            last_flush_at: None,
            last_error: None,
        }
    }
}

enum Command {
    Write(Vec<u8>),
    WriteBatch(Vec<Vec<u8>>),
    Flush(Sender<io::Result<()>>),
    Sync(Sender<io::Result<()>>),
    Rotate(Sender<io::Result<()>>),
    Stats(Sender<FileLoggerStats>),
    Shutdown(Sender<FileLoggerStats>),
}

/// Minimum queue capacity to prevent unbounded memory growth.
/// If a caller specifies `None` or `0`, this value is used instead.
const MIN_QUEUE_CAPACITY: usize = 64;

impl FileLogger {
    pub fn new(config: FileLoggerConfig) -> io::Result<Self> {
        // FIX: Enforce minimum capacity to prevent unbounded memory growth.
        // Previously, `None` or `0` would create an unbounded channel, allowing
        // a fast producer to exhaust memory. Now we clamp to MIN_QUEUE_CAPACITY.
        let capacity = match config.queue_capacity {
            Some(cap) if cap > 0 => cap,
            _ => MIN_QUEUE_CAPACITY,
        };
        let (command_tx, command_rx) = bounded(capacity);
        let (file, current_size) = open_log_file(&config, false)?;

        let session_id = Arc::new(AtomicU64::new(
            config
                .session_id
                .unwrap_or_else(|| rand::rng().random_range(..=9999999999)),
        ));

        let worker_config = config;
        let handle = thread::spawn(move || {
            let writer = BufWriter::with_capacity(worker_config.buffer_size, file);
            let mut state = WorkerState::new(worker_config, writer, current_size);
            worker_loop(command_rx, &mut state)
        });
        let inner = Arc::new(FileLoggerInner {
            command_tx,
            join: Mutex::new(Some(handle)),
            shutdown: AtomicBool::new(false),
            final_stats: Mutex::new(None),
        });
        Ok(Self { inner, session_id })
    }

    pub fn log<T>(&self, entry: T) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.log_with_header(entry, true)
    }

    pub fn log_with_header<T>(&self, entry: T, add_header: bool) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        let payload = if add_header {
            self.format_log_entry(entry.as_ref())
        } else {
            entry.as_ref().to_vec()
        };
        self.send_command(Command::Write(payload))
    }

    pub fn try_log<T>(&self, entry: T) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.try_log_with_header(entry, true)
    }

    pub fn try_log_with_header<T>(&self, entry: T, add_header: bool) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        let payload = if add_header {
            self.format_log_entry(entry.as_ref())
        } else {
            entry.as_ref().to_vec()
        };
        self.try_send_command(Command::Write(payload))
    }

    pub fn log_batch<I, T>(&self, entries: I) -> io::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.log_batch_with_header(entries, true)
    }

    pub fn log_batch_with_header<I, T>(&self, entries: I, add_header: bool) -> io::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        // FIX: Use size_hint to preallocate Vec capacity for sized iterators,
        // reducing repeated reallocations during batch collection.
        let iter = entries.into_iter();
        let (size_hint, _) = iter.size_hint();
        let mut batch = Vec::with_capacity(size_hint);
        for entry in iter {
            let payload = if add_header {
                self.format_log_entry(entry.as_ref())
            } else {
                entry.as_ref().to_vec()
            };
            batch.push(payload);
        }
        if batch.is_empty() {
            return Ok(());
        }
        self.send_command(Command::WriteBatch(batch))
    }

    pub fn try_log_batch<I, T>(&self, entries: I) -> io::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.try_log_batch_with_header(entries, true)
    }

    pub fn try_log_batch_with_header<I, T>(&self, entries: I, add_header: bool) -> io::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        // FIX: Use size_hint to preallocate Vec capacity for sized iterators,
        // reducing repeated reallocations during batch collection.
        let iter = entries.into_iter();
        let (size_hint, _) = iter.size_hint();
        let mut batch = Vec::with_capacity(size_hint);
        for entry in iter {
            let payload = if add_header {
                self.format_log_entry(entry.as_ref())
            } else {
                entry.as_ref().to_vec()
            };
            batch.push(payload);
        }
        if batch.is_empty() {
            return Ok(());
        }
        self.try_send_command(Command::WriteBatch(batch))
    }

    pub fn session_id(&self) -> u64 {
        self.session_id.load(Ordering::Relaxed)
    }

    pub fn set_session_id(&self, sid: u64) {
        self.session_id.store(sid, Ordering::Relaxed);
    }

    fn format_log_entry(&self, message: &[u8]) -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let sid = self.session_id.load(Ordering::Relaxed);

        // Format: time=<epoch>, sid=<session_id>, <message>
        let mut payload = Vec::with_capacity(128 + message.len());
        // The unwrap is safe because writing to a Vec<u8> will not fail.
        write!(payload, "time={}, sid={}, ", timestamp, sid).unwrap();
        payload.extend_from_slice(message);
        payload
    }

    pub fn flush(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.send_command(Command::Flush(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn try_flush(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.try_send_command(Command::Flush(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn sync(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.send_command(Command::Sync(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn try_sync(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.try_send_command(Command::Sync(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn rotate(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.send_command(Command::Rotate(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn try_rotate(&self) -> io::Result<()> {
        let (tx, rx) = bounded(1);
        self.try_send_command(Command::Rotate(tx))?;
        Self::recv_io_result(rx)
    }

    pub fn stats(&self) -> io::Result<FileLoggerStats> {
        if self.inner.shutdown.load(Ordering::SeqCst)
            && let Some(stats) = self.inner.final_stats.lock().unwrap().clone()
        {
            return Ok(stats);
        }
        let (tx, rx) = bounded(1);
        self.send_command(Command::Stats(tx))?;
        rx.recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "logger worker disconnected"))
    }

    pub fn shutdown(&self) -> io::Result<FileLoggerStats> {
        if self.inner.shutdown.swap(true, Ordering::SeqCst) {
            if let Some(stats) = self.inner.final_stats.lock().unwrap().clone() {
                return Ok(stats);
            }
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file logger already shut down",
            ));
        }

        let (tx, rx) = bounded(1);
        self.inner
            .command_tx
            .send(Command::Shutdown(tx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "logger worker disconnected"))?;

        let final_stats = rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "logger worker disconnected"))?;

        let mut join_guard = self.inner.join.lock().unwrap();
        let mut stats_guard = self.inner.final_stats.lock().unwrap();

        if let Some(handle) = join_guard.take() {
            match handle.join() {
                Ok(stats) => {
                    *stats_guard = Some(stats.clone());
                    Ok(stats)
                }
                Err(_) => {
                    *stats_guard = Some(final_stats.clone());
                    Err(io::Error::other("logger worker panicked during shutdown"))
                }
            }
        } else {
            *stats_guard = Some(final_stats.clone());
            Ok(final_stats)
        }
    }

    fn send_command(&self, command: Command) -> io::Result<()> {
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file logger is shutting down",
            ));
        }

        self.inner
            .command_tx
            .send(command)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "logger worker disconnected"))
    }

    fn try_send_command(&self, command: Command) -> io::Result<()> {
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file logger is shutting down",
            ));
        }

        match self.inner.command_tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "logger queue is full",
            )),
            Err(TrySendError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "logger worker disconnected",
            )),
        }
    }

    fn recv_io_result<T>(rx: Receiver<io::Result<T>>) -> io::Result<T> {
        match rx.recv() {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "logger worker disconnected",
            )),
        }
    }
}

impl Clone for FileLogger {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            session_id: Arc::clone(&self.session_id),
        }
    }
}

impl fmt::Debug for FileLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileLogger")
            .field("shutdown", &self.inner.shutdown.load(Ordering::SeqCst))
            .finish()
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }

        if self.inner.shutdown.load(Ordering::SeqCst) {
            if let Some(handle) = self.inner.join.lock().unwrap().take() {
                let _ = handle.join();
            }
            return;
        }

        let _ = self.shutdown();
    }
}

struct WorkerState {
    config: FileLoggerConfig,
    base_path: PathBuf,
    writer: Option<BufWriter<File>>,
    current_size: u64,
    dirty: bool,
    next_auto_flush: Option<Instant>,
    start_instant: Instant,
    stats: FileLoggerStats,
}

impl WorkerState {
    fn new(config: FileLoggerConfig, writer: BufWriter<File>, current_size: u64) -> Self {
        let base_path = config.base_path();
        let stats = FileLoggerStats::new_started();
        let now = Instant::now();
        let next_auto_flush = config.auto_flush_interval.map(|interval| now + interval);

        Self {
            config,
            base_path,
            writer: Some(writer),
            current_size,
            dirty: false,
            next_auto_flush,
            start_instant: now,
            stats,
        }
    }

    fn handle_write(&mut self, mut payload: Vec<u8>) -> io::Result<()> {
        if self.config.ensure_newline && !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }

        let len = payload.len() as u64;
        self.rotate_if_needed(len)?;
        if let Some(writer) = self.writer.as_mut() {
            writer.write_all(&payload)?;
        } else {
            panic!(
                "File logger writer is unavailable due to a rotation failure. Panicking to prevent silent data loss."
            );
        }
        self.current_size += len;
        self.stats.bytes_written += len;
        self.stats.records_written += 1;
        self.dirty = true;
        if let Some(interval) = self.config.auto_flush_interval {
            self.next_auto_flush = Some(Instant::now() + interval);
        }
        Ok(())
    }

    fn handle_batch(&mut self, batch: Vec<Vec<u8>>) -> io::Result<()> {
        for payload in batch {
            self.handle_write(payload)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer.as_mut() {
            writer.flush()?;
            if self.config.sync_on_flush {
                writer.get_ref().sync_all()?;
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file logger writer unavailable (flush)",
            ));
        }
        if self.dirty {
            self.dirty = false;
            self.stats.flush_count += 1;
            self.stats.last_flush_at = Some(SystemTime::now());
        }
        if let Some(interval) = self.config.auto_flush_interval {
            self.next_auto_flush = Some(Instant::now() + interval);
        }
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        if let Some(writer) = self.writer.as_ref() {
            writer.get_ref().sync_all()?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file logger writer unavailable (sync)",
            ));
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Ensure all buffered data is on disk before rotating
        self.flush()?;

        // Close current file handle so rotation works on Windows too
        if let Some(old_writer) = self.writer.take() {
            drop(old_writer);
        }

        // Attempt rotation of existing files
        let rotation_result = rotate_files(&self.base_path, self.config.max_rotate_files);
        if let Err(ref err) = rotation_result {
            self.record_error(err);
        }

        // Reopen the active log file regardless of rotation outcome
        let rotated_ok = rotation_result.is_ok();
        let (file, size) = if rotated_ok {
            open_log_file(&self.config, true)? // start a fresh file
        } else {
            // Reopen existing file in append mode to remain operational
            open_log_file(&self.config, false)?
        };

        self.writer = Some(BufWriter::with_capacity(self.config.buffer_size, file));
        self.current_size = if rotated_ok { 0 } else { size };
        self.dirty = false;
        if let Some(interval) = self.config.auto_flush_interval {
            self.next_auto_flush = Some(Instant::now() + interval);
        }
        if rotated_ok {
            self.stats.rotate_count += 1;
            Ok(())
        } else {
            rotation_result
        }
    }

    fn rotate_if_needed(&mut self, incoming_len: u64) -> io::Result<()> {
        if let Some(limit) = self.config.rotate_size_bytes
            && limit > 0
            && self.current_size + incoming_len > limit
        {
            self.rotate()?;
        }
        Ok(())
    }

    fn flush_if_due(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(deadline) = self.next_auto_flush
            && Instant::now() >= deadline
        {
            self.flush()?;
        }
        Ok(())
    }

    fn snapshot_stats(&mut self) -> FileLoggerStats {
        let mut stats = self.stats.clone();
        stats.uptime = self.start_instant.elapsed();
        stats
    }

    fn finalize(&mut self) -> FileLoggerStats {
        if let Err(err) = self.flush() {
            self.record_error(&err);
        }
        let mut stats = self.stats.clone();
        stats.uptime = self.start_instant.elapsed();
        stats
    }

    fn record_error(&mut self, err: &io::Error) {
        self.stats.last_error = Some(err.to_string());
    }
}

fn worker_loop(command_rx: Receiver<Command>, state: &mut WorkerState) -> FileLoggerStats {
    loop {
        let command = match state.config.auto_flush_interval {
            Some(interval) => match command_rx.recv_timeout(interval) {
                Ok(command) => command,
                Err(RecvTimeoutError::Timeout) => {
                    if let Err(err) = state.flush_if_due() {
                        state.record_error(&err);
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            },
            None => match command_rx.recv() {
                Ok(command) => command,
                Err(_) => break,
            },
        };

        match command {
            Command::Write(payload) => {
                if let Err(err) = state.handle_write(payload) {
                    state.record_error(&err);
                }
            }
            Command::WriteBatch(batch) => {
                if let Err(err) = state.handle_batch(batch) {
                    state.record_error(&err);
                }
            }
            Command::Flush(reply) => {
                let result = state.flush();
                if let Err(ref err) = result {
                    state.record_error(err);
                }
                let _ = reply.send(result);
            }
            Command::Sync(reply) => {
                let result = state.sync();
                if let Err(ref err) = result {
                    state.record_error(err);
                }
                let _ = reply.send(result);
            }
            Command::Rotate(reply) => {
                let result = state.rotate();
                if let Err(ref err) = result {
                    state.record_error(err);
                }
                let _ = reply.send(result);
            }
            Command::Stats(reply) => {
                let stats = state.snapshot_stats();
                let _ = reply.send(stats);
            }
            Command::Shutdown(reply) => {
                let final_stats = state.finalize();
                let _ = reply.send(final_stats.clone());
                return final_stats;
            }
        }

        if let Err(err) = state.flush_if_due() {
            state.record_error(&err);
        }
    }

    state.finalize()
}

fn rotate_files(base_path: &Path, max_files: usize) -> io::Result<()> {
    if max_files == 0 {
        if let Err(err) = fs::remove_file(base_path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(err);
        }
        return Ok(());
    }

    for index in (1..=max_files).rev() {
        let src = if index == 1 {
            base_path.to_path_buf()
        } else {
            rotated_path(base_path, index - 1)
        };
        let dst = rotated_path(base_path, index);

        if dst.exists()
            && let Err(err) = fs::remove_file(&dst)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(err);
        }

        if src.exists()
            && let Err(err) = fs::rename(&src, &dst)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(err);
        }
    }

    Ok(())
}

fn rotated_path(base_path: &Path, index: usize) -> PathBuf {
    let mut rotated = base_path.to_path_buf();
    let name = base_path
        .file_name()
        .map(|file_name| format!("{}.{}", file_name.to_string_lossy(), index))
        .unwrap_or_else(|| format!("log.{index}"));
    rotated.set_file_name(name);
    rotated
}

fn open_log_file(config: &FileLoggerConfig, truncate: bool) -> io::Result<(File, u64)> {
    let path = config.base_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }

    let file = options.open(&path)?;
    let size = if truncate { 0 } else { file.metadata()?.len() };
    Ok((file, size))
}
