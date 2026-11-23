"""Parser for the TPM 2.0 measured-boot (TCG2 crypto-agile) event log.

Firmware records every component it runs before the OS into TPM PCRs and
writes the same events to this log. Windows keeps one log per boot in
C:\\Windows\\Logs\\MeasuredBoot. Replaying the log gives the value each PCR
should hold, so two boots can be compared without talking to the TPM.

This module only parses bytes it is given. It makes no claim that the log is
genuine: a log is trustworthy only when the TPM's own PCRs match it, which
Windows checks separately (`PcrsMatchTcgLog`).
"""
import hashlib
import struct

SHA256 = 0x000B
_DIGEST_SIZES = {0x0004: 20, 0x000B: 32, 0x000C: 48, 0x000D: 64, 0x0012: 32}

EV_NO_ACTION = 0x00000003
EV_SEPARATOR = 0x00000004
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0

MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 20000
MAX_EVENT_BYTES = 1024 * 1024
PCRS = tuple(range(24))


class LogError(ValueError):
    """The bytes are not a complete, well-formed TCG2 event log."""


def _take(data, offset, size):
    if size < 0 or offset + size > len(data):
        raise LogError("event log is truncated")
    return data[offset:offset + size], offset + size


def _variable_name(event):
    """The UEFI variable name of an EFI_VARIABLE_DATA event, or ''."""
    if len(event) < 32:
        return ""
    name_len, _data_len = struct.unpack_from("<QQ", event, 16)
    if name_len > 128 or 32 + name_len * 2 > len(event):
        return ""
    try:
        name = event[32:32 + name_len * 2].decode("utf-16-le")
    except UnicodeDecodeError:
        return ""
    return name if name.isprintable() else ""


def parse(data):
    """Events of a TCG2 log as dicts: pcr, type, digest (SHA-256 hex), name."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_LOG_BYTES:
        raise LogError("event log is missing or over the size bound")
    # The first record uses the SHA-1 layout and carries the Spec ID event,
    # which lists the digest algorithms every later record contains.
    header, offset = _take(data, 0, 32)
    _pcr, event_type, _digest, size = struct.unpack("<II20sI", header)
    if event_type != EV_NO_ACTION or size > MAX_EVENT_BYTES:
        raise LogError("first record is not a Spec ID event")
    spec, offset = _take(data, offset, size)
    if not spec.startswith(b"Spec ID Event03\x00") or len(spec) < 28:
        raise LogError("not a TPM 2.0 crypto-agile log")
    count = struct.unpack_from("<I", spec, 24)[0]
    if not 1 <= count <= 8 or len(spec) < 28 + count * 4:
        raise LogError("Spec ID algorithm list is malformed")
    sizes = {}
    for i in range(count):
        alg, digest_size = struct.unpack_from("<HH", spec, 28 + i * 4)
        sizes[alg] = digest_size
    if sizes.get(SHA256) != 32:
        raise LogError("log has no SHA-256 bank")

    events = []
    while offset < len(data):
        if len(events) >= MAX_EVENTS:
            raise LogError("event budget exhausted")
        head, offset = _take(data, offset, 12)
        pcr, event_type, digest_count = struct.unpack("<III", head)
        if pcr == 0xFFFFFFFF and event_type == 0xFFFFFFFF:
            break       # unused tail of a preallocated log
        if pcr >= 24 or digest_count != count:
            raise LogError("event header is malformed")
        digest = None
        for _ in range(digest_count):
            raw, offset = _take(data, offset, 2)
            alg = struct.unpack("<H", raw)[0]
            if alg not in sizes or sizes[alg] != _DIGEST_SIZES.get(alg, sizes[alg]):
                raise LogError("event names an undeclared digest algorithm")
            value, offset = _take(data, offset, sizes[alg])
            if alg == SHA256:
                digest = value
        raw, offset = _take(data, offset, 4)
        size = struct.unpack("<I", raw)[0]
        if size > MAX_EVENT_BYTES:
            raise LogError("event body is over the size bound")
        body, offset = _take(data, offset, size)
        if digest is None:
            raise LogError("event has no SHA-256 digest")
        name = ""
        if event_type in (EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_AUTHORITY):
            name = _variable_name(body)
        events.append({"pcr": pcr, "type": event_type,
                       "digest": digest.hex(), "name": name})
    if not events:
        raise LogError("event log holds no measurements")
    return events


def replay(events):
    """PCR index -> hex value after extending every measured event.

    EV_NO_ACTION records are informational and never extended. The result is a
    fingerprint for comparing boots; a PCR started at a non-zero locality
    differs from the TPM's value by that constant only.
    """
    pcrs = {i: bytes(32) for i in PCRS}
    for event in events:
        if event["type"] == EV_NO_ACTION:
            continue
        pcrs[event["pcr"]] = hashlib.sha256(
            pcrs[event["pcr"]] + bytes.fromhex(event["digest"])).digest()
    return {i: value.hex() for i, value in pcrs.items()}


def summary(data):
    """What one boot measured, reduced to comparable facts."""
    events = parse(data)
    pcrs = replay(events)

    def digests(kind, pcr):
        return sorted({e["digest"] for e in events
                       if e["type"] == kind and e["pcr"] == pcr})

    variables = {}
    for e in events:
        if e["type"] == EV_EFI_VARIABLE_DRIVER_CONFIG and e["name"]:
            variables.setdefault(e["name"], e["digest"])
    return {
        "events": len(events),
        "pcrs": {str(i): pcrs[i] for i in range(8)},
        # PCR 2: code from option ROMs and plug-in cards, outside the firmware.
        "option_roms": digests(EV_EFI_BOOT_SERVICES_DRIVER, 2)
                       + digests(EV_EFI_RUNTIME_SERVICES_DRIVER, 2),
        # PCR 4: every EFI application the firmware started (boot managers).
        "boot_apps": digests(EV_EFI_BOOT_SERVICES_APPLICATION, 4),
        # PCR 7: Secure Boot variables and the authorities used this boot.
        "variables": {k: variables[k] for k in sorted(variables)
                      if k in ("SecureBoot", "PK", "KEK", "db", "dbx")},
        "authorities": digests(EV_EFI_VARIABLE_AUTHORITY, 7),
    }
