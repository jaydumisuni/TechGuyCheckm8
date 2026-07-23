//! Lease-bound, backup-gated SysCfg selected-field write transport.
//!
//! This crate permits exactly one catalogued Diagnostic or Calibration field
//! per transaction. A verified Phase 5G encrypted backup is reopened and
//! authenticated before any serial port is opened. The existing SysCfg
//! transaction engine then performs the precondition read, typed write,
//! immediate read-back, automatic rollback, and recovery escalation.

mod pipeline;
mod transport;

pub use pipeline::{
    execute_selected_write_with_serialport, execute_selected_write_with_transport,
    required_write_transport_permissions, SelectedNonIdentityFieldWrite,
    SelectedWriteEvidence, SelectedWriteRequest, WriteTransportAuthorization,
};
pub use transport::{SerialportSysCfgWriteTransport, WriteFramePolicy};

pub const SYSCFG_WRITE_TRANSPORT_VERSION: &str = "tgcheckm8.syscfg-write-transport.v1";
pub const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const ABSOLUTE_MAX_TIMEOUTS: u16 = 64;
pub const ABSOLUTE_MAX_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SysCfgWriteTransportError {
    #[error("unsupported SysCfg write transport version: {0}")]
    UnsupportedVersion(String),
    #[error("invalid response limit: {0}")]
    InvalidResponseLimit(usize),
    #[error("invalid read chunk size: {0}")]
    InvalidChunkSize(usize),
    #[error("invalid consecutive timeout limit: {0}")]
    InvalidTimeoutLimit(u16),
    #[error("write transport permission grant does not match the exact contract")]
    PermissionGrantMismatch,
    #[error("explicit selected-field write authorization is required")]
    ExplicitAuthorizationRequired,
    #[error("control-line side effects were not acknowledged")]
    ControlLineAcknowledgementRequired,
    #[error("session identity does not match")]
    SessionMismatch,
    #[error("device identity does not match")]
    DeviceIdentityMismatch,
    #[error("provider identity does not match")]
    ProviderIdentityMismatch,
    #[error("board configuration does not match")]
    BoardConfigurationMismatch,
    #[error("serial lease has expired")]
    LeaseExpired,
    #[error("verified rollback-ready backup evidence does not match the current scope")]
    BackupScopeMismatch,
    #[error("encrypted rollback package could not be reopened and verified: {0}")]
    BackupVerification(String),
    #[error("rollback package did not parse into the locked full SysCfg snapshot: {0}")]
    BackupParse(String),
    #[error("selected field is not catalogued")]
    UnknownSelectedField,
    #[error("selected field class is not an approved non-identity class")]
    BlockedSelectedFieldClass,
    #[error("selected field is not enabled by both provider policies")]
    SelectedFieldNotWritable,
    #[error("selected field value is unchanged")]
    UnchangedSelectedValue,
    #[error("SysCfg transaction plan was rejected: {0}")]
    TransactionPlan(String),
    #[error("prepared transaction did not contain exactly the selected field")]
    TransactionPlanMismatch,
    #[error("serial port open failed: {0}")]
    OpenFailed(String),
    #[error("serial input-buffer clear failed: {0}")]
    ClearFailed(String),
    #[error("serial command is outside the fixed print/add surface")]
    CommandSurfaceViolation,
    #[error("serial command write failed: {0}")]
    WriteFailed(String),
    #[error("serial flush failed: {0}")]
    FlushFailed(String),
    #[error("serial response read failed: {0}")]
    ReadFailed(String),
    #[error("serial response exceeded the bounded size: {0}")]
    ResponseTooLarge(usize),
    #[error("serial prompt timed out after {timeout_count} timeouts and {response_bytes} bytes")]
    PromptTimeout {
        response_bytes: usize,
        timeout_count: u16,
    },
}
