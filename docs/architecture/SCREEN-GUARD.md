# Screen Guard: a local screen model that helps the user avoid harm

Status: design, 2026-10-31. Nothing here is built or deployed yet.

Owner request: a custom computer-vision model, trained by us, that watches the
screen locally to help the user avoid harmful actions, with a calculated
sampling rate, data that never leaves the machine and that disappears safely.
Owner decisions (2026-10-31): all three uses below; **off until the user turns
it on**.

A security product that captures the screen is what Argus reports as spyware
elsewhere (`spy`, `privacy`, the privacy seal). Screen Guard is held to the
rules Argus applies to everyone else, and stricter ones.

## What it does

| Use | How | When |
| --- | --- | --- |
| **Stop scams on screen** | A small on-device classifier recognises fake login pages, scam pop-ups, fake "virus found" alerts, tech-support scams and ransom notes, and warns before the user acts. | Continuously while on, on the schedule below |
| **Spot hidden remote control** | The same classifier recognises screen-share and remote-control overlays. It corroborates what Argus already sees without pixels (remote-access processes, inbound sessions); a visual sign alone is never called a compromise. | Continuously while on |
| **Guide everyday tasks** | The user asks "what should I do here?"; one frame goes to a local vision model through Ollama (`jarvis model install`, PR #8), and the frame is then destroyed. | Only on request, never continuous |

## Invariants

1. **Off by default.** Nothing is captured until the user turns it on, in the
   desktop app, after a plain explanation. One switch stops it.
2. **Visible.** While Screen Guard can capture, the tray icon shows it, and the
   desktop app says so on every screen.
3. **No pixels persist.** A frame exists only in memory: captured, reduced to
   the model's input and a perceptual fingerprint, the full-size buffer
   zeroed, the reduced input classified, then zeroed. No frame, crop,
   thumbnail or recognised text is written to disk, logged, sent to the
   daemon, or sent anywhere.
4. **Decisions only, briefly, in memory.** What is kept is a decision: time,
   label, confidence, the foreground application's executable name. Benign
   decisions are not kept (only the last screen's fingerprint and label, to
   skip re-classifying it). Warnings stay in the app's memory for 24 hours,
   at most 500, for the user to review; turning Screen Guard off clears them.
   Nothing is written to disk, so there is nothing to delete securely later.
   (Chosen over a SQLite log with `secure_delete`: WAL files, journals and
   SSD wear-levelling make on-disk deletion hard to guarantee, and the cost of
   memory-only is that a restart forgets the last day's warnings.)
5. **Never captures** while the screen is locked, on the secure desktop (UAC,
   sign-in), during the privacy seal, while the user has paused it, or after
   60 s without input. A state that cannot be read counts as refusing.
6. **Advice, not action.** Screen Guard warns and explains. It never clicks,
   types, closes windows or changes the system (Maximum Assurance: model
   output cannot authorise a protected action).
7. **Bounded cost.** At most one frame every 2 s, about 1 % of one CPU core
   while active, nothing while idle; it backs off under load.
8. **Trained without user data.** The model is trained on synthetic and public
   examples only. No user screen is ever used for training or leaves the
   machine. Evaluation on a user's machine counts decisions, never frames.

## How often to look

`scripts/dev/screen_guard_sampling.py` reproduces every number here.

A harmful screen stays up for a dwell time before the person acts. Verizon's
2024 DBIR measured a median of about 28 s from opening a phishing email to
entering data. The dwell is modelled as lognormal with that median and
sigma 1 (the spread is an assumption; the script takes others). A warning
needs two agreeing frames, so one odd frame never alarms. A miss is a dwell
shorter than the time to collect them.

| Interval while active | Miss, timer only | Miss, timer + capture on change | Frames per active hour | CPU (25 ms per frame) |
| --- | --- | --- | --- | --- |
| 1 s | 0.18 % | 0.03 % | 3,600 | 2.5 % |
| **2 s** | 1.3 % | **0.41 %** | 1,800 | 1.25 % |
| 3 s | 3.4 % | 1.3 % | 1,200 | 0.83 % |
| 5 s | 9.4 % | 4.2 % | 720 | 0.5 % |
| 10 s | 26 % | 15 % | 360 | 0.25 % |

A timer alone is the wrong design: at 10 s it misses one scam in four.
Capturing at once when the foreground window or its title changes removes the
wait for the next tick, and a scam page arrives as exactly such a change.

**Schedule:**
- capture immediately on a foreground window or title change;
- every **2 s** for the first 60 s after a change (the window people fall in);
- every **10 s** while the screen is steady;
- **nothing** after 60 s without keyboard or mouse input, or while locked.

Expected: about 0.4 % of scams missed at about 1 % CPU during active use,
zero cost otherwise. The sensitivity is honest: if victims act faster (median
15 s) the 2 s schedule misses 2.1 %; at a median of 60 s, 0.03 %.

## How often it may be wrong

A week of active use (6 h a day) is about 63,000 frames. Consecutive frames
are nearly identical, so their errors are correlated: a model wrong on a
screen is wrong on every frame of it. Budgeting per frame would demand a
false-positive rate of 0.0016 %, which no small model meets.

So Screen Guard classifies **distinct screens**, not frames: each frame's
perceptual fingerprint (a 64-bit difference hash of the reduced image) is
compared with the last one, and an unchanged screen reuses the last decision.
That cuts both cost and the budget's denominator to the screens a person
actually sees, a few thousand a week. The release target is **at most one
false warning per week of active use**, measured as warnings per distinct
benign screen on held-out benign sessions, **and** recall of at least 95 % on
held-out scam screens. A model that misses either does not ship.

## The model

- **Input:** the screen reduced to 256 x 160 grayscale (layout, buttons,
  dialog shapes and large text survive; small text, faces and content do not).
- **Network:** a small convolutional network, depthwise-separable blocks,
  about 0.3 M parameters, 6 classes (benign, fake login, scam pop-up or fake
  alert, tech-support scam, ransom note, remote-control overlay). Run on CPU
  inside the desktop app; the weights ship signed in the release.
- **Training data, synthetic and public only:** HTML templates of real scam
  families and of benign pages rendered headless at many sizes, themes,
  languages and scalings; screenshots of public scam-reporting datasets where
  licences allow; benign desktop states rendered from open-source apps.
  Training is offline and reproducible, never on a user's machine.
- **Evaluation:** held-out families (a scam family is never in both training
  and test), the two targets above, and a calibration check so a stated
  confidence means what it says.

## Where it runs

| Part | Where | Why |
| --- | --- | --- |
| Capture, fingerprint, model | Windows desktop app (Rust) | It already runs in the user's session; capture needs no new process or elevation; no frame crosses a process boundary |
| Warnings | Desktop app, as a native notification; summarised to the daemon as a decision | The daemon records the event like any finding; it never receives pixels |
| Guidance (on request) | Desktop app to the local Ollama on 127.0.0.1 | One frame, one answer, then destroyed |

Alternatives considered: capture in the Python daemon (rejected: it runs in
WSL or as a service account, without the user's desktop, and would move frames
across processes); a vision-language model running continuously (rejected:
seconds per frame and gigabytes of memory, against invariant 7).

## Build order

1. The schedule and the privacy store as pure, tested code: sampler, change
   trigger, idle and lock rules, frame zeroing, fingerprint, decision log with
   TTL (`desktop/src/screenguard.rs`, done 2026-10-31; nothing captures yet).
2. Dataset generator and training pipeline (offline), model card with the
   measured targets.
3. Capture and inference in the desktop app behind the off-by-default switch,
   the visible indicator, and the pause rules.
4. On-request guidance through Ollama.
5. Assurance register entry once capture exists, kept at `unverified` until the targets are
   measured on held-out data and the capture rules are verified on a real
   Windows session.

## What this does not claim

- A missed scam is still possible (about 0.4 % by the model above, more if the
  model is weaker than its targets). Screen Guard adds a check; it does not
  replace caution.
- Reduced frames can still show what is on screen while in memory; the
  guarantee is that they are never stored or sent, and are zeroed after use.
- Visual signs of remote control are corroboration, not proof.

## Advisory review

Jev (`python3 -m scripts.reviews.screen_guard_advisory`, 2026-10-31, design
phase, metadata only): schedule `adaptive` (1.0), placement `app` (1.0),
per-distinct-screen budget sound (0.74), retention consistent (0.84), first
risk to test `capture_when_off` (0.55) ahead of `pixel_persist` (0.43). Both
are covered first: the gate's default refuses everything, and frames are
zeroed on drop. Advisory only; the tests decide.
