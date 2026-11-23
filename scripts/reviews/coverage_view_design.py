"""Jev as a design guide for the /coverage view: rank candidate design moves.

Fixed interface-design metadata only; nothing about the protected machine.
Each candidate is judged on three independent questions, and code combines the
answers (weights and thresholds below, in one place). Jev ranks; it does not
decide. A candidate it likes still has to be truthful, tested and worth its
cost, and one it dislikes can be kept with the reason written down.
"""
import json
import sys

from jarvis.response import jev

STATE = {
    'view': 'a three-dimensional live view of one machine\'s defensive monitoring, left open on a screen',
    'viewer': 'the owner of the machine, who glances at it to learn whether the monitor is working '
              'and what it can and cannot detect',
    'scene': {
        'glass panes on a sphere': 'one per attack technique; lit = a detection was proven to fire, '
                                   'clear with amber rim = mapped but unproven, etched = nothing looks for it',
        'neurons': 'one per collector job; an arc shows time since its last run',
        'firing': 'a signal travels from a neuron to the panes it feeds only when that collector really ran',
        'core': 'the machine; colour is the share of collectors that are current',
    },
    'rules': [
        'nothing may suggest protection or activity the data does not support',
        'decoration is allowed only if it is declared and stops when the view is not live',
        'must stay readable in a light and a dark theme and with reduced motion',
    ],
    'style_wanted': 'futuristic, glass-like, refined, alive',
}

CANDIDATES = {
    'pane_labels': 'the technique identifier is etched on each near pane and readable when the pane is large on screen',
    'result_colour': 'a firing is coloured by what that run reported: cool when it found nothing serious, '
                     'red when it reported a critical or high finding',
    'quiet_axons': 'the lines from a neuron to its panes are drawn very faint until that neuron fires or is pointed at',
    'follow_camera': 'the camera turns by itself toward whichever neuron fired most recently',
    'afterglow': 'after firing, a neuron keeps a fading glow whose length is that collector\'s measured run duration',
    'activity_strip': 'a strip along the bottom shows the last five minutes of firings as ticks on a time axis, '
                      'one row per protection area',
    'ambient_chatter': 'small random flickers travel between neurons at all times so the scene always looks busy',
    'held_style': 'a pane whose probe fires but which is deliberately held at unproven gets a dashed amber rim, '
                  'distinct from a pane that is mapped with no probe at all',
    'overdue_mark': 'a neuron whose run is overdue past its interval grows a slowly widening amber ring '
                    'before it is counted stale',
    'feed_count': 'pane brightness is scaled by how many collectors feed that technique',
}

# What is already drawn that carries no data, or carries it loosely. Judged the
# same way with `--built`: decoration has to earn its place too.
BUILT = {
    'idle_drift': 'every pane floats in and out by a hair, continuously, encoding nothing',
    'sheen': 'a soft band of light slowly crosses the glass every few seconds, encoding nothing',
    'dendrites': 'each neuron has six short static branches that encode nothing and brighten when it fires',
    'bloom': 'bright parts of the scene glow softly into their surroundings',
    'core_rings': 'three thin rings rotate around the core continuously, encoding nothing',
    'inflow_motes': 'motes spiral into the core; how many is set by the number of events the sensor '
                    'committed on its last pass, their motion is continuous',
    'start_signal': 'when the scheduler starts a job a signal runs from the core out to that neuron',
    'intro': 'on first load the panes fly outward into place over about two seconds',
    'breathing_panes': 'lit panes slowly pulse in brightness at all times, encoding nothing',
    'frozen_when_dead': 'when the view stops hearing from the monitor all motion stops and the colour drains out',
}

GLANCE = {'hinders': 'It makes the state of the monitor harder to read at a glance',
          'neutral': 'It neither helps nor hinders a glance read',
          'helps': 'It makes one aspect of the monitor\'s state quicker to read',
          'answers': 'It directly answers whether the monitor is working or what is covered'}
APPEAL = {'gimmick': 'It reads as a gimmick or as clutter',
          'neutral': 'It does not change how refined the view looks',
          'refined': 'It makes the view look more considered and precise',
          'striking': 'It makes the view strikingly more alive and futuristic without clutter'}
ORDER = {'glance': list(GLANCE), 'appeal': list(APPEAL)}

# Composition, kept here for review. Glance value matters most, a misleading
# move is penalised harder than a pretty one is rewarded, and anything Jev
# thinks more likely than not to mislead is not built on its ranking.
WEIGHT = {'glance': 0.55, 'appeal': 0.30, 'misread': 0.60}
MISREAD_LIMIT = 0.5


def questions(candidates=None):
    out = {}
    for key, text in (CANDIDATES if candidates is None else candidates).items():
        out[f'{key}__glance'] = {
            'type': 'choice',
            'instructions': f'Proposed change to the view: {text}. What is its effect on the viewer\'s '
                            'ability to read the state of the monitor at a glance?',
            'criteria': GLANCE}
        out[f'{key}__appeal'] = {
            'type': 'choice',
            'instructions': f'Proposed change to the view: {text}. How does it affect the look of the '
                            'view against the style wanted?',
            'criteria': APPEAL}
        out[f'{key}__misread'] = {
            'type': 'noul',
            'instructions': f'Proposed change to the view: {text}. Could it lead the viewer to believe in '
                            'protection or activity that the data does not support?',
            'criteria': {'true': 'It could mislead in that way', 'false': 'It could not mislead in that way'}}
    if candidates is not None:
        return out
    out['default_reading'] = {
        'type': 'choice',
        'instructions': 'The view has two readings: what is proven, and whether collectors were up over '
                        'the last day. Which default serves a viewer who glances at an always-open screen?',
        'criteria': {'alternate': 'Alternate between the two on a timer',
                     'proven': 'Stay on what is proven until the viewer switches',
                     'uptime': 'Stay on uptime until the viewer switches'}}
    out['theme_default'] = {
        'type': 'choice',
        'instructions': 'Which default theme serves an always-open monitoring view on a personal machine?',
        'criteria': {'system': 'Follow the system light or dark setting',
                     'dark': 'Always start dark', 'light': 'Always start light'}}
    return out


def expected(answer, order):
    """Probability-weighted position on the ordered levels, 0..1."""
    probs = answer['probabilities']
    return sum(probs[level] * i for i, level in enumerate(order)) / (len(order) - 1)


def rank(answers, candidates=None):
    rows = []
    for key in (CANDIDATES if candidates is None else candidates):
        glance = expected(answers[f'{key}__glance'], ORDER['glance'])
        appeal = expected(answers[f'{key}__appeal'], ORDER['appeal'])
        misread = answers[f'{key}__misread']['noul']
        value = WEIGHT['glance'] * glance + WEIGHT['appeal'] * appeal - WEIGHT['misread'] * misread
        rows.append({'candidate': key, 'glance': round(glance, 2), 'appeal': round(appeal, 2),
                     'misread': round(misread, 2), 'value': round(value, 3),
                     'build': misread < MISREAD_LIMIT and value > 0})
    return sorted(rows, key=lambda r: -r['value'])


if __name__ == '__main__':
    built = BUILT if '--built' in sys.argv else None
    try:
        result = jev._call(STATE, questions(built), timeout=40)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
    answers = result['answers']
    for row in rank(answers, built):
        if built is not None:
            row['keep'] = row.pop('build')
        print(json.dumps(row))
    if built is not None:
        sys.exit(0)
    for key in ('default_reading', 'theme_default'):
        print(json.dumps({key: answers[key]['choice'], 'confidence': answers[key]['confidence'],
                          'probabilities': answers[key]['probabilities']}))
