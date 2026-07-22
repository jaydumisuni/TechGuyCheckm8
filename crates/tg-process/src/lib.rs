use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPolicy {
    approved_executable_roots: Vec<PathBuf>,
    approved_working_root: PathBuf,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl ProcessPolicy {
    pub fn new(
        approved_executable_roots: Vec<PathBuf>,
        approved_working_root: PathBuf,
        timeout: Duration,
        poll_interval: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, ProcessError> {
        if approved_executable_roots.is_empty() {
            return Err(ProcessError::MissingExecutableRoots);
        }
        if timeout.is_zero() || poll_interval.is_zero() {
            return Err(ProcessError::InvalidTimeout);
        }
        if max_stdout_bytes == 0 || max_stderr_bytes == 0 {
            return Err(ProcessError::InvalidCaptureLimit);
        }

        let approved_executable_roots = approved_executable_roots
            .into_iter()
            .map(canonical_directory)
            .collect::<Result<Vec<_>, _>>()?;
        let approved_working_root = canonical_directory(approved_working_root)?;

        Ok(Self {
            approved_executable_roots,
            approved_working_root,
            timeout,
            poll_interval,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    Exited,
    TimeoutKilled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub total_bytes: usize,
    pub truncated: bool,
}

impl CapturedStream {
    pub fn utf8_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEvidence {
    pub child_waited: bool,
    pub stdout_joined: bool,
    pub stderr_joined: bool,
}

impl CleanupEvidence {
    pub fn verified(&self) -> bool {
        self.child_waited && self.stdout_joined && self.stderr_joined
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedOutcome {
    pub termination: TerminationReason,
    pub status_code: Option<i32>,
    pub success: bool,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub elapsed_millis: u128,
    pub cleanup: CleanupEvidence,
}

pub fn run_supervised(
    policy: &ProcessPolicy,
    spec: &ProcessSpec,
) -> Result<SupervisedOutcome, ProcessError> {
    let executable = spec.executable.canonicalize()?;
    if !executable.is_file() {
        return Err(ProcessError::ExecutableNotFile(executable));
    }
    if !policy
        .approved_executable_roots
        .iter()
        .any(|root| executable.starts_with(root))
    {
        return Err(ProcessError::ExecutableOutsideApprovedRoot(executable));
    }

    let working_directory = spec.working_directory.canonicalize()?;
    if !working_directory.is_dir()
        || !working_directory.starts_with(&policy.approved_working_root)
    {
        return Err(ProcessError::WorkingDirectoryOutsideApprovedRoot(
            working_directory,
        ));
    }
    validate_environment(&spec.environment)?;

    let mut command = Command::new(&executable);
    command
        .args(&spec.args)
        .current_dir(&working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(&spec.environment);
    apply_platform_environment(&mut command);

    let started = Instant::now();
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or(ProcessError::MissingStdoutPipe)?;
    let stderr = child.stderr.take().ok_or(ProcessError::MissingStderrPipe)?;
    let stdout_thread = capture_thread(stdout, policy.max_stdout_bytes);
    let stderr_thread = capture_thread(stderr, policy.max_stderr_bytes);

    let (status, termination) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, TerminationReason::Exited);
        }
        if started.elapsed() >= policy.timeout {
            terminate_child(&mut child)?;
            let status = child.wait()?;
            break (status, TerminationReason::TimeoutKilled);
        }
        thread::sleep(policy.poll_interval);
    };

    let stdout = join_capture(stdout_thread, "stdout")?;
    let stderr = join_capture(stderr_thread, "stderr")?;
    let cleanup = CleanupEvidence {
        child_waited: true,
        stdout_joined: true,
        stderr_joined: true,
    };

    Ok(SupervisedOutcome {
        termination,
        status_code: status.code(),
        success: status.success() && cleanup.verified(),
        stdout,
        stderr,
        elapsed_millis: started.elapsed().as_millis(),
        cleanup,
    })
}

fn canonical_directory(path: PathBuf) -> Result<PathBuf, ProcessError> {
    let canonical = path.canonicalize()?;
    if !canonical.is_dir() {
        return Err(ProcessError::ExpectedDirectory(canonical));
    }
    Ok(canonical)
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), ProcessError> {
    for (key, value) in environment {
        if key.trim().is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(ProcessError::InvalidEnvironmentKey(key.clone()));
        }
    }
    Ok(())
}

fn capture_thread<R>(reader: R, limit: usize) -> JoinHandle<io::Result<CapturedStream>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || capture_bounded(reader, limit))
}

fn capture_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<CapturedStream> {
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    let mut total_bytes = 0_usize;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(read);
        if bytes.len() < limit {
            let remaining = limit - bytes.len();
            bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok(CapturedStream {
        truncated: total_bytes > bytes.len(),
        bytes,
        total_bytes,
    })
}

fn join_capture(
    handle: JoinHandle<io::Result<CapturedStream>>,
    stream: &'static str,
) -> Result<CapturedStream, ProcessError> {
    let captured = handle
        .join()
        .map_err(|_| ProcessError::CaptureThreadPanicked(stream))??;
    Ok(captured)
}

fn terminate_child(child: &mut std::process::Child) -> Result<(), ProcessError> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) => {
            if child.try_wait()?.is_some() {
                Ok(())
            } else {
                Err(ProcessError::Io(error))
            }
        }
    }
}

#[cfg(windows)]
fn apply_platform_environment(command: &mut Command) {
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(not(windows))]
fn apply_platform_environment(_command: &mut Command) {}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("at least one approved executable root is required")]
    MissingExecutableRoots,
    #[error("timeout and poll interval must be greater than zero")]
    InvalidTimeout,
    #[error("stdout and stderr capture limits must be greater than zero")]
    InvalidCaptureLimit,
    #[error("expected a directory: {0}")]
    ExpectedDirectory(PathBuf),
    #[error("executable is not a file: {0}")]
    ExecutableNotFile(PathBuf),
    #[error("executable is outside approved roots: {0}")]
    ExecutableOutsideApprovedRoot(PathBuf),
    #[error("working directory is outside the approved root: {0}")]
    WorkingDirectoryOutsideApprovedRoot(PathBuf),
    #[error("invalid environment key or NUL-containing value: {0}")]
    InvalidEnvironmentKey(String),
    #[error("worker stdout pipe was unavailable")]
    MissingStdoutPipe,
    #[error("worker stderr pipe was unavailable")]
    MissingStderrPipe,
    #[error("capture thread panicked for {0}")]
    CaptureThreadPanicked(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}
