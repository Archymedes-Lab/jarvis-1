"""Jev as a design guide for the /world view: rank candidate design moves.

Fixed interface-design metadata only; nothing about the protected machine, its
position, or any report it has collected. Each candidate is judged on three
independent questions, and code combines the answers (weights and thresholds
below, in one place). Jev ranks; it does not decide. A candidate it likes still
has to be truthful, tested and worth its cost, and one it dislikes can be kept
with the reason written down.

    python3 scripts/reviews/world_view_design.py            candidates not built yet
    python3 scripts/reviews/world_view_design.py --built    what is already drawn
"""
import json
import sys

from jarvis.response import jev

STATE = {
    'view': 'a three-dimensional heads-up-display globe of where armed conflict is being reported, '
            'on a personal security dashboard',
    'viewer': 'the owner of one computer, who wants to see at a glance where conflict is reported, '
              'what is happening there, and how far it is from them',
    'data': {
        'newsroom reports': 'headlines and videos from named newsrooms, placed where the headline names '
                            'a city or region; a report naming only a country is known only to country level',
        'machine-coded events': 'events coded by software from news articles; their positions are often '
                                'wrong because every place an article mentions is coded',
        'zones': 'clusters of located reports from several independent publishers within two days; '
                 'a cluster shows where reporting concentrates, not a front line',
        'limits': 'report volume follows media attention, not the scale of violence; there is no '
                  'verified casualty, front-line or danger-level data',
    },
    'rules': [
        'nothing may suggest more precision, certainty or danger than the reports support',
        'the page may contact only the dashboard itself, never a third party',
        'motion is allowed only when it means something happened, except a slow turn of the globe',
        'the view must stay clean: few elements, each with a meaning',
    ],
    'style_wanted': 'futuristic, clean, interactive, heads-up-display, three-dimensional',
}

CANDIDATES = {
    'country_tint': 'when reports name only a country, that country\'s outline is drawn brighter, '
                    'instead of a ring at one point inside it',
    'heat_glow': 'a soft heat-map glow spreads around places with many reports',
    'belligerent_arcs': 'animated arcs are drawn between the capitals of the countries named in a report',
    'report_beams': 'each place with reports gets a vertical beam of light whose height is the number of reports',
    'video_thumbnails': 'the hover card shows the video thumbnail image, loaded from the video site',
    'headline_ticker': 'a ticker scrolls the latest headlines continuously along the bottom',
    'radar_sweep': 'a radar sweep line rotates across the globe at all times',
    'rising_pulse': 'a zone\'s bracket pulses only when its reports in the last day clearly exceed the day before',
    'publisher_badge': 'each report dot carries a small number: how many independent publishers reported there',
    'danger_level': 'each zone is coloured green, amber or red by a danger level computed from report volume',
    'casualty_counts': 'casualty numbers found in headlines are added up and shown on each zone',
    'proximity_notice': 'a notice appears when the device or a trusted place is inside, or within 100 km of, a zone',
    'place_search': 'the owner can type a place name and the globe turns to it and lists its reports',
    'zone_history': 'selecting a zone shows a small chart of its reports per six hours over three days',
    'focus_dim': 'when a zone is selected, everything outside it is dimmed',
    'source_strip': 'a compact strip lists every source with the time it last answered and marks the silent ones',
}

# What is already drawn. Judged the same way with `--built`.
BUILT = {
    'dotted_land': 'land is drawn as a grid of small dots with thin country outlines on a dark glass sphere',
    'report_dots': 'a dot per reported place, red for articles and amber for videos, larger for more reports',
    'country_ring': 'a report naming only a country is a hollow ring at the country\'s label point, '
                    'and its card says the exact place is not stated',
    'fresh_pulse': 'a dot pulses only while its newest report is under three hours old',
    'zone_outline': 'a zone is the outline around its reports, with a bracket of fixed screen size so it '
                    'can be found from orbit',
    'hover_card': 'pointing at a dot shows the place, its precision, and the latest headlines with publisher and age',
    'distance_arc': 'an arc joins the device to the nearest zone and is labelled with the distance in kilometres',
    'terminator': 'land on the night side of the Earth is drawn dimmer, from the current time',
    'timeline': 'a bar per hour of the last three days can be scrubbed or replayed to show reports appearing',
    'unfold': 'the globe unfolds into a flat map and back',
    'unverified_layer': 'machine-coded events are hidden unless they sit near a newsroom report, '
                        'and a toggle labelled Unverified shows the rest',
    'slow_turn': 'the globe turns slowly by itself when nothing is selected, and a button stops it',
    'stale_drain': 'when the reports are old or the dashboard stops answering, colour drains and pulses stop',
}

GLANCE = {'hinders': 'It makes it harder to see where conflict is reported and what is happening there',
          'neutral': 'It neither helps nor hinders that',
          'helps': 'It makes one aspect of that quicker to see',
          'answers': 'It directly answers where conflict is reported, what is happening or how far it is'}
APPEAL = {'gimmick': 'It reads as a gimmick or as clutter',
          'neutral': 'It does not change how refined the view looks',
          'refined': 'It makes the view look more considered and precise',
          'striking': 'It makes the view strikingly more futuristic without clutter'}
ORDER = {'glance': list(GLANCE), 'appeal': list(APPEAL)}

# Composition, kept here for review. A misleading move is penalised harder than
# a pretty one is rewarded, and anything Jev thinks more likely than not to
# overstate what the reports support is not built on its ranking.
WEIGHT = {'glance': 0.55, 'appeal': 0.30, 'misread': 0.60}
MISREAD_LIMIT = 0.5

DECISIONS = {
    'machine_coded_default': (
        'Machine-coded events often have wrong positions. How should they appear by default?',
        {'hidden': 'Hidden unless near a newsroom report, with a toggle to show the rest',
         'dim': 'All shown, but smaller and dimmer than newsroom reports',
         'equal': 'All shown the same as newsroom reports'}),
    'zone_shape': (
        'How should a cluster of located reports be drawn?',
        {'outline': 'An outline around the reports themselves',
         'country': 'The whole country filled in',
         'heat': 'A blurred heat map'}),
    'zone_ranking': (
        'Zones are listed in a side panel. Ranked by what?',
        {'reports': 'Number of reports, labelled as report volume',
         'danger': 'A danger score',
         'recency': 'Time of the newest report'}),
    'opening_view': (
        'What should the view open on?',
        {'own_position': 'The globe turned to the owner\'s own position, zones visible around it',
         'busiest_zone': 'The zone with the most reports',
         'whole_map': 'The flat map of the whole world'}),
}


def questions(candidates):
    out = {}
    for key, text in candidates.items():
        out[f'{key}__glance'] = {
            'type': 'choice',
            'instructions': f'Design element of the view: {text}. What is its effect on the viewer\'s '
                            'ability to see where conflict is reported and what is happening there?',
            'criteria': GLANCE}
        out[f'{key}__appeal'] = {
            'type': 'choice',
            'instructions': f'Design element of the view: {text}. How does it affect the look of the '
                            'view against the style wanted?',
            'criteria': APPEAL}
        # Two narrow questions. One broad "could it mislead or break a rule" question was
        # tried first (2026-10-04) and answered 0.42-0.94 for everything, a place search
        # and the land dots included, so it could not separate candidates.
        out[f'{key}__overstates'] = {
            'type': 'noul',
            'instructions': f'Design element of the view: {text}. Does this element, by itself, present '
                            'something the data does not contain: a measured danger level, a casualty '
                            'figure, a front line, a relationship between parties, or a position more '
                            'exact than the report gives?',
            'criteria': {'true': 'It presents something the data does not contain',
                         'false': 'It presents only what the data contains'}}
        out[f'{key}__idle'] = {
            'type': 'noul',
            'instructions': f'Design element of the view: {text}. Does this element move or animate '
                            'continuously even when no new report has arrived, or load anything from '
                            'a third-party site?',
            'criteria': {'true': 'It moves without new data or loads from a third party',
                         'false': 'It does neither'}}
    return out


def expected(answer, order):
    """Probability-weighted position on the ordered levels, 0..1."""
    probs = answer['probabilities']
    return sum(probs[level] * i for i, level in enumerate(order)) / (len(order) - 1)


def rank(answers, candidates):
    rows = []
    for key in candidates:
        glance = expected(answers[f'{key}__glance'], ORDER['glance'])
        appeal = expected(answers[f'{key}__appeal'], ORDER['appeal'])
        misread = max(answers[f'{key}__overstates']['noul'], answers[f'{key}__idle']['noul'])
        value = WEIGHT['glance'] * glance + WEIGHT['appeal'] * appeal - WEIGHT['misread'] * misread
        rows.append({'candidate': key, 'glance': round(glance, 2), 'appeal': round(appeal, 2),
                     'misread': round(misread, 2), 'value': round(value, 3),
                     'build': misread < MISREAD_LIMIT and value > 0})
    return sorted(rows, key=lambda r: -r['value'])


if __name__ == '__main__':
    built = '--built' in sys.argv
    candidates = BUILT if built else CANDIDATES
    asked = questions(candidates)
    if not built:
        for key, (text, criteria) in DECISIONS.items():
            asked[key] = {'type': 'choice', 'instructions': text, 'criteria': criteria}
    try:
        result = jev._call(STATE, asked, timeout=40)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
    answers = result['answers']
    for row in rank(answers, candidates):
        if built:
            row['keep'] = row.pop('build')
        print(json.dumps(row))
    if not built:
        for key in DECISIONS:
            print(json.dumps({key: answers[key]['choice'], 'confidence': answers[key]['confidence'],
                              'probabilities': answers[key]['probabilities']}))
