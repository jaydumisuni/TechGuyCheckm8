# Phase 4C — Fixed Read-only Apple Probes

## Purpose

Connect the supervised process boundary to the Apple observation layer without giving the UI or a manifest authority to run arbitrary commands.

The first probe profile is the official `irecovery -q` information query. The upstream implementation prints CPID, ECID, PWND provider, mode, product type, hardware model and display name. It does not select a send, exploit, reset, reboot or restore action.

## Fixed profile

```text
profile: i_recovery_dfu_query
executable: installed and approved separately
arguments: exactly ["-q"]
environment: cleared
stdin: null
stdout/stderr: bounded
timeout: mandatory
shell: never
```

No manifest field or UI input can add another argument.

Recovery-mode results are rejected by this first profile. It proves DFU and pwned-DFU observations only. Recovery and Purple transports will receive separate profiles and proof requirements.

## Permissions

The fixed profile declares exactly:

- `device_observe`
- `usb_read`
- `process_spawn`

A manifest with more or fewer permissions fails validation. A session missing any required permission is blocked before process execution.

`usb_write`, serial write, Arduino control, restore, exploit, ramdisk and SysCfg permissions are not accepted by this profile.

## Executable provenance

Source provenance and executable approval are separate.

A research manifest may record:

- upstream repository;
- exact source commit;
- declared licence;
- supported hosts;
- required permissions and proofs.

It may leave `expected_executable_sha256` unset. Such a probe is tracked but cannot run.

Execution requires:

1. a 64-hex SHA-256 pin in the manifest;
2. an installed file under an approved executable root;
3. the installed file hash matching the manifest;
4. a supported host;
5. a valid policy profile;
6. all fixed read-only permissions.

Stable policy additionally requires Stable maturity and a declared licence.

## Parsing and privacy

The parser accepts only the known information fields:

- `CPID`
- `ECID`
- `PWND`
- `MODE`
- `PRODUCT`
- `MODEL`
- `NAME`

CPID and ECID are normalized as hexadecimal values. The raw query output is never placed into durable evidence. It is converted immediately into the redacted Apple observation contract.

The resulting evidence stores:

- probe and executable identity;
- granted read-only permissions;
- process exit and cleanup evidence;
- output truncation state;
- elapsed time;
- redacted Apple observation.

It does not store the raw ECID or complete `irecovery -q` output.

## Doctor

The probe Doctor reports independently:

- manifest validity;
- executable presence;
- host support;
- SHA-256 match;
- overall readiness;
- deterministic findings.

An unpinned research probe is intentionally not ready.

## Tests

The phase includes a synthetic executable that accepts only `-q` and prints the official query shape with fake identifiers. It proves:

- the supervisor invokes the fixed argument;
- process cleanup is verified;
- pwned DFU is observed from `PWND: usbliter8`;
- raw ECID does not appear in serialized evidence;
- missing USB-read permission blocks execution;
- manifests cannot expand permissions;
- unpinned research probes cannot run;
- malformed identities and unsupported modes fail closed;
- hash mismatches block before execution.

The synthetic executable is a test fixture and must be excluded from release packaging.

## Deliberate exclusions

This phase does not:

- bundle or download `irecovery`;
- approve any current host binary;
- execute a real USB probe in CI;
- enter DFU;
- pwn a device;
- boot Purple/Diags;
- open serial or DCSD;
- read or write SysCfg;
- expose arbitrary process arguments.

## Next gate

A real read-only probe pack requires reproducible host builds, per-platform SHA-256 pins, licence notices, clean-host tests and hardware observations from Windows, macOS and Linux. Only then may it be promoted from `discovered` to hardware-tested Beta or Stable.
