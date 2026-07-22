from pathlib import Path

lib_path = Path("crates/tg-serial-platform/src/lib.rs")
text = lib_path.read_text(encoding="utf-8")

old_mut = "let mut port = build_port(port_name, settings)"
if text.count(old_mut) != 1:
    raise SystemExit(f"expected one mutable port binding, found {text.count(old_mut)}")
text = text.replace(old_mut, "let port = build_port(port_name, settings)", 1)

session_block = '''#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDoctorSession {
    pub report: SerialDoctorReport,
    pub lease: LeaseGrant,
}
'''
reservation_block = session_block + '''
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDoctorReservation {
    pub owner: LeaseOwner,
    pub current_tick: u64,
    pub ttl_ticks: u64,
}
'''
if text.count(session_block) != 1:
    raise SystemExit("platform session block was not found exactly once")
text = text.replace(session_block, reservation_block, 1)

old_signature = '''pub fn reserve_and_run_doctor<P: SerialOpenProbe>(
    manifest: &SerialDoctorManifest,
    context: &SerialDoctorContext,
    host: HostPlatform,
    observations: &[RawSerialPortObservation],
    probe: &mut P,
    leases: &mut LeaseManager,
    owner: LeaseOwner,
    current_tick: u64,
    ttl_ticks: u64,
) -> Result<PlatformDoctorSession, SerialPlatformError> {
    if owner.session_id != context.session_id {
'''
new_signature = '''pub fn reserve_and_run_doctor<P: SerialOpenProbe>(
    manifest: &SerialDoctorManifest,
    context: &SerialDoctorContext,
    host: HostPlatform,
    observations: &[RawSerialPortObservation],
    probe: &mut P,
    leases: &mut LeaseManager,
    reservation: PlatformDoctorReservation,
) -> Result<PlatformDoctorSession, SerialPlatformError> {
    if reservation.owner.session_id != context.session_id {
'''
if text.count(old_signature) != 1:
    raise SystemExit("old reserve_and_run_doctor signature was not found exactly once")
text = text.replace(old_signature, new_signature, 1)

old_lease = "let lease = acquire_preopen_lease(leases, &selected, owner.clone(), current_tick, ttl_ticks)?;"
new_lease = '''let lease = acquire_preopen_lease(
        leases,
        &selected,
        reservation.owner.clone(),
        reservation.current_tick,
        reservation.ttl_ticks,
    )?;'''
if text.count(old_lease) != 1:
    raise SystemExit("pre-open lease call was not found exactly once")
text = text.replace(old_lease, new_lease, 1)

release_old = "leases.release(lease.lease_id, &owner)"
if text.count(release_old) != 3:
    raise SystemExit(f"expected three owner release calls, found {text.count(release_old)}")
text = text.replace(release_old, "leases.release(lease.lease_id, &reservation.owner)")
lib_path.write_text(text, encoding="utf-8")

test_path = Path("crates/tg-serial-platform/tests/platform_flow.rs")
tests = test_path.read_text(encoding="utf-8")
old_import = "OpenSafetyAcknowledgement, SerialPlatformError, SerialportOpenProbe,"
new_import = "OpenSafetyAcknowledgement, PlatformDoctorReservation, SerialPlatformError, SerialportOpenProbe,"
if tests.count(old_import) != 1:
    raise SystemExit("platform test import marker was not found exactly once")
tests = tests.replace(old_import, new_import, 1)

old_args = '''        owner,
        10,
        30,
'''
new_args = '''        PlatformDoctorReservation {
            owner,
            current_tick: 10,
            ttl_ticks: 30,
        },
'''
if tests.count(old_args) != 3:
    raise SystemExit(f"expected three reservation argument groups, found {tests.count(old_args)}")
tests = tests.replace(old_args, new_args)
test_path.write_text(tests, encoding="utf-8")
