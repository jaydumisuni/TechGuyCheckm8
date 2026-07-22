# Serial platform adapter doctrine

## Scope

`tg-serial-platform` is the first real host adapter beneath the Serial Doctor. It uses the exact `serialport` crate version `4.9.0` for cross-platform enumeration and guarded opening.

The adapter does not send serial data, read a prompt, enter Purple mode, or issue SysCfg commands.

## Dependency pin

```toml
serialport = {
  version = "=4.9.0",
  default-features = false,
  features = ["usbportinfo-interface"]
}
```

Default features are disabled to avoid a mandatory Linux `libudev` runtime/build dependency. Reduced Linux metadata is accepted only as discovery input; the Serial Doctor still rejects ambiguous or weak candidates.

## Inventory

The backend calls `serialport::available_ports()` and retains USB serial ports only. Non-USB, PCI, Bluetooth and unknown ports are counted but not passed to the Purple/SysCfg route.

The operational observation contains:

- host port path;
- USB VID/PID;
- adapter serial number when available;
- manufacturer and product strings;
- USB interface index when available.

The interface index is bound into the in-memory serial identity so multiple interfaces from one composite USB device cannot silently collapse into one candidate. The durable Doctor receipt remains hash-only.

## macOS dual-port handling

macOS commonly exposes both `/dev/cu.*` and `/dev/tty.*` for one serial interface. When both paths have the same suffix and identical USB metadata, the backend retains the callout (`/dev/cu.*`) path and records one removed duplicate.

It does not deduplicate unrelated devices merely because their VID/PID or product strings match.

## Guarded open

Port opening requires an explicit `OpenSafetyAcknowledgement`.

This is necessary because the upstream serial library documents that Linux can assert DTR briefly while opening a port even when DTR preservation is requested. Therefore, “zero serial bytes written” does not mean “electrically side-effect free.”

The adapter:

1. refuses to open without explicit acknowledgement;
2. requests DTR preservation;
3. requests exclusive access on Unix;
4. applies fixed baud/data/parity/stop/timeout settings;
5. re-reads the applied settings;
6. attempts a second open while the first handle is alive;
7. accepts exclusivity only when the second open fails;
8. closes both handles without read or write calls;
9. reports zero bytes written and zero bytes read.

## Lease ordering

The platform adapter selects the candidate and acquires the serial resource lease before opening the port. If open, settings verification, exclusivity, or the Doctor verdict fails, the lease is released immediately.

A successful ready report retains the lease for the following SysCfg provider stage.

## Promotion requirements

Hardware promotion requires recorded evidence for every supported host and adapter combination:

- inventory metadata and driver state;
- exact candidate rule;
- exclusive-open result;
- DTR/control-line behaviour;
- disconnect/reconnect behaviour;
- COM/TTY renumbering;
- duplicate-interface behaviour;
- serial settings read-back;
- no serial data transferred;
- lease cleanup after failure.

No production adapter rule is promoted by this phase.
