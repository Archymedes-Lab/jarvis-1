"""Jev as a design guide for the /procs grid redesign: rank candidate design moves.

Fixed interface-design metadata only: no screenshots, no process names, no
counts from the protected machine. Each candidate is judged on three
independent questions (glance value, appeal, risk of implying activity), and
code combines the answers with the same weights as coverage_view_design.py.
Jev ranks; it does not decide. A candidate it likes still has to be truthful,
tested and worth its cost; one it dislikes can be kept with the reason written.
"""
import json
import sys

from jarvis.response import jev
from scripts.reviews.coverage_view_design import (
    APPEAL,
    GLANCE,
    MISREAD_LIMIT,
    ORDER,
    WEIGHT,
    expected,
)

STATE = {
    'view': 'a three-dimensional live map of every running process on one personal computer '
            '(a Windows host with a Linux virtual machine inside it), left open on a screen',
    'viewer': 'the owner of the machine, who glances at it to learn whether anything unfamiliar is running '
              'and which programs are busy',
    'scale': 'about three hundred processes on the host and about sixty in the Linux machine',
    'judgments': {
        'unfamiliar': 'never seen on this machine, or a familiar name running from an unfamiliar place',
        'new today': 'name or binary first seen today',
        'calm': 'seen before',
        'not judged': 'no history to compare against yet',
        'missing': 'a watched protective process that was running and is not now',
        'short-lived': 'a start recorded by the event sensor that ended before the table could sample it',
    },
    'rules': [
        'nothing may suggest activity or safety the data does not support',
        'motion only when something happened; when the feed is not live, motion stops and colour drains',
        'never rely on colour alone; readable in light and dark themes and with reduced motion',
    ],
    'style_wanted': 'grid based, glass cubes, aesthetic, slick, calm',
}

CANDIDATES = {
    'grid_districts': 'processes are glass cubes on a floor grid, one district per operating system and, inside '
                      'it, one block per parent program, with the parent name written on the floor beside each block',
    'cpu_height': 'a cube\'s height and its inner glow grow with its processor use, and its footprint grows with '
                  'its memory on a logarithmic scale',
    'verdict_markers': 'an unfamiliar process is a red cube with a small diamond marker floating above it; a process '
                       'new today is an amber cube with a triangle marker; calm processes have no marker',
    'start_rim': 'a process started in the last five minutes has a thin bright rim around the top of its cube, '
                 'which does not move and disappears after five minutes',
    'birth_ease': 'when a process starts its cube grows out of the floor over half a second with a brief flash; '
                  'when it exits the cube sinks into the floor over half a second',
    'ghost_rise': 'a start that ended before it could be sampled appears as a hollow cube above its parent\'s block '
                  'that rises and fades out over two seconds',
    'missing_hollow': 'a watched protective process that stopped is drawn as a hollow dashed outline of a cube in a '
                      'row at the front of its district',
    'refraction': 'the floor grid is seen bent through each glass cube, and the cubes reflect a soft sky',
    'glow_pools': 'busy cubes cast a soft coloured glow on the floor in the dark theme and a soft contact shadow '
                  'in the light theme',
    'alarm_beat': 'rings pulse outward around every unfamiliar process every two and a half seconds for as '
                  'long as it runs',
    'block_reflow': 'when a parent program gains enough children that its block needs another row, the blocks '
                    'after it slide to their new place over half a second',
    'idle_shimmer': 'a faint light sweeps across the glass every few seconds, encoding nothing',
}


def questions():
    out = {}
    for key, text in CANDIDATES.items():
        out[f'{key}__glance'] = {
            'type': 'choice',
            'instructions': f'Proposed design for the view: {text}. What is its effect on the viewer\'s ability to '
                            'read the state of the machine\'s processes at a glance?',
            'criteria': GLANCE}
        out[f'{key}__appeal'] = {
            'type': 'choice',
            'instructions': f'Proposed design for the view: {text}. How does it affect the look of the view '
                            'against the style wanted?',
            'criteria': APPEAL}
        # The first run (2026-10-29) asked "could it mislead" and every candidate
        # scored 0.73-0.92, including plain outlines: the question did not
        # discriminate. This asks for the typical viewer and the likely reading.
        out[f'{key}__misread'] = {
            'type': 'noul',
            'instructions': f'Proposed design for the view: {text}. Given the legend on screen, is a typical '
                            'viewer more likely than not to conclude that something happened on the machine, or '
                            'that it is safe or in danger, when the data behind the view does not say so?',
            'criteria': {'true': 'Yes, the typical viewer would likely draw a conclusion the data does not support',
                         'false': 'No, the typical viewer would read it as the data says'}}
    out['legible_300'] = {
        'type': 'noul',
        'instructions': 'With about three hundred translucent calm cubes in a grid, can a viewer find two or three '
                        'unfamiliar processes within a few seconds when each is a red opaque cube with a diamond '
                        'marker above it and its name written beside it?',
        'criteria': {'true': 'Yes, they stand out within a few seconds',
                     'false': 'No, they are likely to be lost among the rest'}}
    out['camera_default'] = {
        'type': 'choice',
        'instructions': 'Which default camera serves a glance at a grid of about three hundred cubes of varying '
                        'height?',
        'criteria': {'isometric': 'A high three-quarter view, about 35 degrees above the floor',
                     'top_down': 'Straight down, a flat map where height is not visible',
                     'low_angle': 'A low view close to the floor, heights dramatic, rear rows hidden'}}
    out['height_scale'] = {
        'type': 'choice',
        'instructions': 'Processor use is near zero for most processes and a few use a lot. Which height scale '
                        'serves a glance?',
        'criteria': {'linear': 'Height proportional to processor use; idle cubes flat, busy ones tall',
                     'sqrt': 'Height proportional to the square root of processor use; small loads visible, '
                             'order kept, stated in the legend',
                     'steps': 'Three fixed heights: idle, busy, very busy'}}
    return out


def rank(answers):
    rows = []
    for key in CANDIDATES:
        glance = expected(answers[f'{key}__glance'], ORDER['glance'])
        appeal = expected(answers[f'{key}__appeal'], ORDER['appeal'])
        misread = answers[f'{key}__misread']['noul']
        value = WEIGHT['glance'] * glance + WEIGHT['appeal'] * appeal - WEIGHT['misread'] * misread
        rows.append({'candidate': key, 'glance': round(glance, 2), 'appeal': round(appeal, 2),
                     'misread': round(misread, 2), 'value': round(value, 3),
                     'build': misread < MISREAD_LIMIT and value > 0})
    return sorted(rows, key=lambda r: -r['value'])


if __name__ == '__main__':
    try:
        result = jev._call(STATE, questions(), timeout=40)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
    answers = result['answers']
    for row in rank(answers):
        print(json.dumps(row))
    print(json.dumps({'legible_300': round(answers['legible_300']['noul'], 2)}))
    for key in ('camera_default', 'height_scale'):
        print(json.dumps({key: answers[key]['choice'], 'confidence': answers[key]['confidence'],
                          'probabilities': answers[key]['probabilities']}))
