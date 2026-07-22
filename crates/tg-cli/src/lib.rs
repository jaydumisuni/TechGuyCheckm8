use std::fs;
use std::path::Path;

use serde_json::json;
use tg_contracts::{validate_engine_for_policy, EngineManifest};
use tg_journal::verify_file;

pub fn execute<I, S>(args: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(CliError::Usage(usage()));
    };

    match command {
        "status" if args.len() == 1 => Ok(serde_json::to_string_pretty(&json!({
            "product": "TGCHECKM8",
            "phase": "gateway-process-foundation",
            "device_access": false,
            "gateway_bind": "loopback_only",
            "worker_execution": "simulator_only",
            "model_authority": false,
            "commands": ["status", "verify-journal", "inspect-engine"]
        }))?),
        "verify-journal" if args.len() == 2 => verify_journal(Path::new(&args[1])),
        "inspect-engine" if args.len() == 2 || args.len() == 3 => {
            let profile = args.get(2).map(String::as_str).unwrap_or("stable");
            inspect_engine(Path::new(&args[1]), profile)
        }
        "help" | "--help" | "-h" => Ok(usage()),
        "status" | "verify-journal" | "inspect-engine" => Err(CliError::Usage(usage())),
        other => Err(CliError::UnknownCommand(other.to_owned())),
    }
}

fn verify_journal(path: &Path) -> Result<String, CliError> {
    let verification = verify_file(path)?;
    Ok(serde_json::to_string_pretty(&json!({
        "verified": true,
        "session_id": verification.session_id,
        "entries": verification.entries,
        "last_sequence": verification.last_sequence,
        "last_hash": verification.last_hash
    }))?)
}

fn inspect_engine(path: &Path, profile: &str) -> Result<String, CliError> {
    if !matches!(profile, "stable" | "beta" | "development") {
        return Err(CliError::InvalidProfile(profile.to_owned()));
    }
    let bytes = fs::read(path)?;
    let manifest: EngineManifest = serde_json::from_slice(&bytes)?;
    let policy_result = validate_engine_for_policy(&manifest, profile);
    Ok(serde_json::to_string_pretty(&json!({
        "engine_id": manifest.engine_id,
        "version": manifest.version,
        "maturity": manifest.maturity,
        "profile": profile,
        "policy_valid": policy_result.is_ok(),
        "policy_error": policy_result.err().map(|error| error.to_string()),
        "capabilities": manifest.capabilities,
        "requested_permissions": manifest.requested_permissions,
        "modifies_device": manifest.modifies_device,
        "requires_network": manifest.requires_network,
        "provenance": manifest.provenance
    }))?)
}

pub fn usage() -> String {
    [
        "TGCHECKM8 read-only CLI",
        "",
        "Usage:",
        "  tgcheckm8 status",
        "  tgcheckm8 verify-journal <events.jsonl>",
        "  tgcheckm8 inspect-engine <engine.json> [stable|beta|development]",
        "",
        "This phase exposes no device-changing command.",
    ]
    .join("\n")
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("unknown read-only command: {0}")]
    UnknownCommand(String),
    #[error("invalid policy profile: {0}")]
    InvalidProfile(String),
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Journal(#[from] tg_journal::JournalError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
