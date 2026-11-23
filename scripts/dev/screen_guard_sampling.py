#!/usr/bin/env python3
"""How often Screen Guard should look: miss rate and cost by sampling interval.

    python3 scripts/dev/screen_guard_sampling.py [--median 28] [--sigma 1.0] [--confirm 2]

Model (docs/architecture/SCREEN-GUARD.md):
  * a harmful screen (a fake login page, a scam pop-up) is on screen for a
    dwell time D before the person acts on it. Verizon's 2024 DBIR puts the
    median time from opening a phishing email to entering data at about 28 s;
    D is modelled lognormal with that median and sigma 1 (the spread is an
    assumption: change it and re-run);
  * a warning needs `confirm` consecutive frames that agree, so one odd frame
    never raises an alarm;
  * timer only: the first frame lands at a uniform phase in [0, T);
  * timer plus change trigger: a new window or page is captured at once,
    so the phase wait disappears (a harmful page arrives as such a change).
A miss is a dwell shorter than the time to collect `confirm` agreeing frames.
"""

import argparse
import math
import random


def miss_rate(dwell, interval, confirm, on_change, rng):
    miss = 0
    for d in dwell:
        phase = 0.0 if on_change else rng.uniform(0, interval)
        if d < phase + (confirm - 1) * interval:
            miss += 1
    return miss / len(dwell)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--median", type=float, default=28.0, help="median dwell, seconds")
    ap.add_argument("--sigma", type=float, default=1.0, help="lognormal sigma of the dwell")
    ap.add_argument("--confirm", type=int, default=2, help="agreeing frames needed for a warning")
    ap.add_argument("--frame-ms", type=float, default=25.0, help="CPU per frame: capture, downscale, model")
    ap.add_argument("--samples", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    dwell = [math.exp(math.log(args.median) + args.sigma * rng.gauss(0, 1)) for _ in range(args.samples)]
    print(f"{'T (s)':>6} {'miss, timer':>12} {'miss, +change':>14} {'frames/active h':>16} {'CPU %':>6}")
    for t in (1, 2, 3, 4, 5, 8, 10, 15):
        print(f"{t:6} {miss_rate(dwell, t, args.confirm, False, rng):12.3%} "
              f"{miss_rate(dwell, t, args.confirm, True, rng):14.3%} {3600 / t:16.0f} "
              f"{100 * args.frame_ms / 1000 / t:6.2f}")


if __name__ == "__main__":
    main()
