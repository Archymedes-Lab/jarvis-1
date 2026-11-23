"""Hardware-backed trust: challenge kernel truth instead of worshipping it.

Layers: USER MODE -> KERNEL -> VBS/HYPERVISOR -> HARDWARE. A kernel sensor
is stronger than user-mode enumeration but lives in the same trust domain
as the OS; a privileged kernel compromise can interfere with both. So the
kernel is never absolute truth: JARVIS surfaces Secure Boot, VBS, HVCI /
Memory Integrity, driver signing and kernel protection status alongside
every high-assurance claim, and downgrades kernel-dependent verdicts when
the floor beneath them is off.

Pure, bounded, no IO. Callers supply already-collected posture booleans.
"""

TRUST_TIERS = ("USER", "KERNEL", "VBS", "HARDWARE")


def assess(*, secure_boot=False, vbs=False, hvci=False,
           driver_signing_enforced=True, kernel_protected=True):
    """Assess the integrity floor under kernel claims. Pure."""
    signals = {"secure_boot": bool(secure_boot), "vbs": bool(vbs),
               "hvci": bool(hvci),
               "driver_signing_enforced": bool(driver_signing_enforced),
               "kernel_protected": bool(kernel_protected)}
    if vbs and hvci and secure_boot:
        tier, confidence = "VBS", 0.85
        note = ("hypervisor-isolated floor: kernel claims are "
                "independently anchored")
    elif secure_boot and driver_signing_enforced and kernel_protected:
        tier, confidence = "KERNEL", 0.6
        note = ("kernel floor only: assumes the Windows kernel is not "
                "compromised; VBS/HVCI absent so a kernel attacker could "
                "interfere with the sensor too")
    else:
        tier, confidence = "USER", 0.3
        note = ("user-mode floor: boot/driver protections missing or "
                "unknown; kernel claims are corroboration, not anchors")
    missing = sorted(k for k, v in signals.items() if not v)
    return {"tier": tier, "confidence": confidence, "signals": signals,
            "missing": missing, "note": note}
