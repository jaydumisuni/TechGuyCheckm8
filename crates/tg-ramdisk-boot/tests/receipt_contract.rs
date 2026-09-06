use tg_process::TerminationReason;
use tg_ramdisk_boot::BootProcessReceipt;

#[test]
fn boot_process_receipt_carries_the_applied_process_bounds() {
    let receipt = BootProcessReceipt {
        step_index: 1,
        instruction: "send_asset:IBSS".to_owned(),
        executable_sha256: "a".repeat(64),
        asset_role: None,
        asset_sha256: None,
        termination: TerminationReason::Exited,
        status_code: Some(0),
        process_success: true,
        cleanup_verified: true,
        stdout_sha256: "b".repeat(64),
        stderr_sha256: "c".repeat(64),
        stdout_bytes: 12,
        stderr_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        elapsed_millis: 4,
        timeout_millis: 5_000,
        max_stdout_bytes: 4_096,
        max_stderr_bytes: 4_096,
    };

    assert_eq!(receipt.termination, TerminationReason::Exited);
    assert_eq!(receipt.timeout_millis, 5_000);
    assert_eq!(receipt.max_stdout_bytes, 4_096);
    assert_eq!(receipt.max_stderr_bytes, 4_096);
    assert!(!receipt.stdout_truncated);
    assert!(!receipt.stderr_truncated);
}
