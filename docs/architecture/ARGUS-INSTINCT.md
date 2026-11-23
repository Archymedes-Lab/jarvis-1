# ARGUS-INSTINCT: one product, one install

Owner decision, 2026-11-02: the system developed here as JARVIS (shown as ARGUS-1 since
2026-10-27) is **ARGUS-INSTINCT**, the edition people install on their computers. It is the
most capable build: on this machine it runs 73 collectors against 47 for the ARGUS-1 server
build and 56 for the ARGUS-1 native Windows build (measured 2026-11-02, every collector of
both is also in ARGUS-INSTINCT). Everything is unified into it.

## What the name covers now

- Everything a person sees says ARGUS-INSTINCT: the dashboard and its pages, the desktop app
  (window, tray, notifications, 11 languages), email, webhook, ntfy, syslog, the phone payload,
  Windows toasts from the independent monitor, service descriptions, the licence line item.
- Text that still says JARVIS inside the daemon is shown as ARGUS-INSTINCT by one display rule,
  kept identical in six places: `jarvis/core/brand.py`, the `brand:begin` blocks of the web
  pages, `desktop/ui/src/lib/brand.ts`, `desktop/src/brand.rs`, `jarvis-health-monitor.ps1`
  (`Format-Brand`). `tests/test_ui_brand.py` keeps them equal. The rule never rewrites
  "ARGUS-1" or "ARGUS-INSTINCT", so text that passed through it twice, or the product build
  that turns JARVIS into ARGUS, stays correct.

## What keeps its old name, and why

These are identities, not text. Renaming them in place would orphan data, evidence or
installed supervisors:

- the `jarvis` Python package, `jarvis.service`, `/opt/jarvis`, `~/.jarvis` (store, event log,
  vault inbox, anchors): history, baselines and acknowledgements live there;
- `C:\ProgramData\Jarvis\Vault` (administrator-only evidence vault);
- Windows task names ("JARVIS independent health monitor", "jarvis reviver", ...), which the
  installed supervisors and Task Scheduler look up by name;
- `service: "JARVIS"` in `/api/health`, which the installed Windows monitors check;
- finding titles (acknowledgement and incident identity); `X-JARVIS-Token`;
- the desktop app identifier `local.jarvis.desktop` (its saved settings).

Renaming those needs a migration release: copy then verify each store, re-register the
Windows tasks under new names, accept both health service names for one release, keep the
vault path or move it with the elevated broker, and roll back if any readback fails.

## One product

- Source of truth: this codebase. The user downloads are built from it by the signed CI
  pipeline in the private Argus-1 repository (`release/`, `docs/guides/RELEASING.md`); the
  server and native editions are packagings of the same code, not separate products.
- The 2026.10.31 ARGUS-1 builds installed on this machine (Linux `argus.service` on port 8790,
  native Windows `python -m argus serve` on 8792 with its own input hook) duplicate collection
  and are retired in favour of ARGUS-INSTINCT. One install per machine.

## What would make us reconsider

A user platform ARGUS-INSTINCT cannot cover (a plain Linux server without the Windows side is
covered by the same code with Windows collectors not applicable; a Windows machine without
WSL needs the native host mode, which measured 11 of 54 detectors verified on 2026-11-02 and
is not ready).
