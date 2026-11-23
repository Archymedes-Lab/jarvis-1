# Running ARGUS-INSTINCT under its own account (the default)

The daemon should run as the system account `jarvis`, not as you. Run as you,
anything running under your account can stop it, rewrite its store, change its
alert settings and read its API token. That includes a malicious download, a
compromised browser extension or a Windows program reading
`\\wsl.localhost`. This is PROTECTION-REVIEW-2026-10-21 F2 and ARGUS-2026-001.

**A deploy is required.** This guide needs a release that contains the
2026-10-30 API hardening:
- paired clients;
- the all-routes credential;
- the state-directory check;
- the CLI guard.

Deploy it first (docs/guides/DEPLOY.md), then switch. Switching an older
release does not secure it, because the older release does not check the state
directory and still hands its token to every local account.

## What changes

| | Before (runs as you) | After (runs as `jarvis`) |
|---|---|---|
| State | `~/.jarvis` | `/var/lib/jarvis/.jarvis`, directory 0700, files 0600, owner `jarvis` |
| API token file | readable by you and by Windows through `\\wsl.localhost` | readable by `jarvis` only |
| Store commands (`jarvis status`, `ack`, `fix`, ...) | `jarvis ...` | `sudo jarvis-svc ...`; plain `jarvis ...` refuses and prints this form |
| API callers (`jarvis brief --check`, quickstart, `ui_check`) | read the token file | a paired client token in `~/.config/jarvis/client.token` |
| Desktop app on Windows | paired token in `%APPDATA%\local.jarvis.desktop\client.token` | the same |
| Windows supervisors (reviver, health monitor) | liveness without a token; details and `/api/run` need a paired token in `%LOCALAPPDATA%\Jarvis\client.token` | the same |
| Browser on Windows | `/pair` page, once per browser | the same |
| Browser on this Linux account | dashboard cookie, on a browser navigation only | `/pair` page, once per browser: your account cannot read the token file, so handing it the cookie would grant it to every process you run (QC blocker 4) |
| Self-check timer | user timer as you | system timer as `jarvis` |

The daemon refuses to start under the service account if its state directory
or any token, key, database or settings file in it is open to group or others.
That check is in `jarvis/core/statedir.py`, and it runs from `serve()`.

## Switch over

1. Deploy the release (DEPLOY.md) and write the usual baseline.
2. Check, changing nothing:

   ```
   sudo scripts/repair/install-service-user.sh --preflight
   ```

   This checks that `jarvis` can run `powershell.exe` through interop, can read
   the sensor spool and can read the running release. If any check fails, stop:
   the daemon stays as it is.
3. Switch:

   ```
   sudo scripts/repair/install-service-user.sh
   ```

   The script does the following, in order:
   - stops the daemon;
   - copies `~/.jarvis` to `/var/lib/jarvis/.jarvis` (your copy is kept);
   - makes every directory 0700 and every file 0600;
   - writes `/etc/jarvis/service-account.json` and `/usr/local/sbin/jarvis-svc`;
   - installs the drop-in;
   - moves the self-check to `jarvis`;
   - starts the daemon and waits for `/api/live`.

   If `/api/live` does not answer, the script rolls back by itself.

   Or run `./install.sh --service-account`, which does `--priority` and then this
   step.
4. Pair what can no longer read the token file:

   ```
   sudo jarvis-svc desktop pair --name cli | jarvis desktop save
   sudo jarvis-svc desktop pair --name desktop
   sudo jarvis-svc desktop pair --name supervisor
   ```

   - **`cli`:** the first line saves the token to `~/.config/jarvis/client.token`
     (0600).
   - **`desktop`:** save the printed token, on one line, as
     `%APPDATA%\local.jarvis.desktop\client.token` on Windows. Unpaired, the
     app shows these steps instead of data.
   - **`supervisor`:** save it as `%LOCALAPPDATA%\Jarvis\client.token`, readable
     by your Windows account only. The reviver and health monitor then get
     source details and can queue re-runs. Without it they see liveness only.
   - **Browsers:** from the desktop app, press Ctrl K and choose **Open in your
     browser** (or Settings → Browser → Open). The browser opens a one-time
     link (single use, two minutes, code in the URL fragment), pairs itself as
     a new client named `browser opened from the app`, and goes on to the page. Without the
     app, `jarvis desktop browser` prints and opens the same kind of link. The
     manual path still works: open `http://localhost:8787/`, and on `/pair`
     paste a token from `sudo jarvis-svc desktop pair --name browser`.
   - **Prometheus:** see docs/architecture/ARGUS-SERVER.md (W7).

   To list or revoke paired clients:

   ```
   sudo jarvis-svc desktop clients
   sudo jarvis-svc desktop revoke ID
   ```

## Verify on real results

The acceptance gate is the same as for a deploy:
- `systemctl show jarvis -p User` reads `User=jarvis`;
- every collector is FRESH within 15 minutes;
- native coverage is complete;
- broker results are accepted.

Then check that the change did what it should:
- `sudo -u jarvis stat -c '%a %U' /var/lib/jarvis/.jarvis /var/lib/jarvis/.jarvis/api.token`
  shows `700 jarvis` and `600 jarvis`;
- `cat /var/lib/jarvis/.jarvis/api.token` as yourself fails with permission denied;
- `curl -s localhost:8787/api/state` without a token answers 403;
- `curl -s localhost:8787/api/health` shows only the liveness fields;
- `jarvis status` refuses and prints the `sudo jarvis-svc status` form.

**Measured later, not yet:**
- that Windows can no longer read the token through
  `\\wsl.localhost\<distro>\var\lib\jarvis\.jarvis\api.token`.

  WSL serves that share as the distribution's default user. That user is you,
  not `jarvis`, so a 0700 directory should refuse it.

  Code check (2026-10-30): no Windows component in the repository reads
  `~/.jarvis` or the token file. The desktop app used the page cookie and now
  uses its paired token, and the supervisors read only repository scripts over
  the share.

  Record the measured result here after the switch.
- that the WSL localhost relay (NAT mode) or mirrored networking presents
  Windows connections as unattributable. If so, Windows browsers and apps must
  pair, which is the intended behaviour.

## Roll back

```
sudo scripts/repair/install-service-user.sh --rollback
```

This does the following:
- removes the drop-in, the marker, `jarvis-svc`, the system self-check and its
  sudoers rule;
- restarts the unit as you, on your untouched `~/.jarvis`;
- re-enables your self-check timer.

`/var/lib/jarvis` is left in place for inspection. Anything the daemon recorded
while running as `jarvis` is there, not in `~/.jarvis`. Copy it back by hand if
you need it.

Rollback does not undo the API hardening. Clients you paired stay paired, and
unpaired Windows clients still see liveness only.

## Why this design

- **Store access through the API instead:** moving every CLI command onto the
  API was weighed and rejected for now. About 40 commands read the store
  directly, and a generic "run this CLI command" API route would be a remote
  command channel.
- **`sudo jarvis-svc` instead:** it keeps them working with one explicit
  privilege step.
- **What would cause reconsideration:** the remaining store commands gaining
  dedicated API routes.
- **The readers group the earlier script used (store 0640) is gone:** any
  process of yours could read the evidence and the token through it, which is
  what this change closes.
