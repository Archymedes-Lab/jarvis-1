"""Fixed engineering metadata only; advisory, never authorization to capture or deploy."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'an opt-in, local, custom screen classifier that warns about scam screens and remote-control '
            'overlays, plus on-request task guidance, with no pixels persisted',
    'consent': 'off until the user turns it on; visible indicator while on',
    'measured': {
        'dwell_model': 'lognormal dwell, median 28 s (published phishing-to-data-entry median), sigma 1 assumed',
        'confirm_frames': 2,
        'miss_timer_only': {'1s': 0.0018, '2s': 0.0133, '5s': 0.094, '10s': 0.263},
        'miss_with_change_trigger': {'1s': 0.0003, '2s': 0.0041, '5s': 0.042, '10s': 0.151},
        'cpu_per_frame_ms_assumed': 25,
        'frames_per_active_week': 63000,
    },
    'alternatives': [
        'fixed 10 s timer',
        'fixed 2 s timer',
        'change-triggered capture, 2 s for 60 s after a change, 10 s steady, none idle or locked',
        'continuous local vision-language model',
    ],
    'placement_alternatives': ['in the user-session desktop app (Rust)', 'in the background daemon (Python, WSL)'],
    'selected': {'schedule': 'change-triggered adaptive', 'placement': 'desktop app'},
    'false_alarm_target': 'at most one false warning per week of active use, counted per distinct screen '
                          '(perceptual hash), and at least 95% recall on held-out scam families',
    'invariants': [
        'nothing captured until opted in; never while locked, secure desktop, privacy seal or paused',
        'frames in memory only, zeroed after inference; never written, logged or sent',
        'only decisions persist; warnings kept 24 h then deleted with secure_delete',
        'advice only, never acts on the system',
        'trained on synthetic and public data only',
    ],
}
QUESTIONS = {
    'schedule': {'type': 'choice', 'instructions':
        'Which capture schedule best balances missed scams against cost and privacy given the measured table?',
        'criteria': {'fixed10': 'fixed 10 s timer', 'fixed2': 'fixed 2 s timer',
                     'adaptive': 'change-triggered adaptive schedule',
                     'vlm': 'continuous vision-language model', 'uncertain': 'Insufficient information'}},
    'placement': {'type': 'choice', 'instructions':
        'Where should capture and inference run to minimise frames crossing process boundaries?',
        'criteria': {'app': 'desktop app in the user session', 'daemon': 'background daemon',
                     'uncertain': 'Insufficient information'}},
    'distinct_screens': {'type': 'noul', 'instructions':
        'Is budgeting false alarms per distinct screen (perceptual hash) rather than per frame a sound '
        'way to make the false-alarm target achievable for a small model?',
        'criteria': {'true': 'Sound', 'false': 'Unsound'}},
    'retention': {'type': 'noul', 'instructions':
        'Is keeping warning decisions (no pixels) for 24 hours and benign decisions only in memory '
        'consistent with the privacy goal?',
        'criteria': {'true': 'Consistent', 'false': 'Too long or too much'}},
    'first_risk': {'type': 'choice', 'instructions':
        'Which risk most deserves the first deterministic test?',
        'criteria': {'capture_when_off': 'a capture while consent is off, paused or locked',
                     'pixel_persist': 'pixels or text reaching disk or a log',
                     'retention': 'decisions outliving their TTL',
                     'cost': 'sampling faster than the schedule under bursty window changes'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
