"""Read-only startup tracing with explicit evidence limits; no trust-by-name."""
import argparse
import json
import os
import re
from datetime import datetime

from jarvis.core.paths import win_script
from jarvis.platform.windows import aslist, ps_json

from .evidence.manifest import Manifest, sha256_file
from .evidence.paths import case_dir

CONSOLES = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wsl.exe', 'conhost.exe',
            'openconsole.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe'}
UNKNOWN_GUIDS = {'', '-', '{00000000-0000-0000-0000-000000000000}'}


def _base(path):
    return (path or '').replace('/', '\\').rsplit('\\', 1)[-1].lower()


def _stamp(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (AttributeError, ValueError, TypeError):
        return None


def _arguments(command):
    match = re.match(r'^\s*(?:"[^"]+"|\S+)\s*(.*)$', command or '', re.S)
    return match.group(1).strip() if match else ''


def _configured_tasks(process, tasks):
    """Command equality names a configured task, not a trusted execution."""
    return [(t.get('path') or '') + (t.get('name') or '') for t in tasks
            if any(_base(a.get('execute')) == _base(process.get('Image'))
                   and (a.get('arguments') or '').strip() == _arguments(process.get('CommandLine'))
                   for a in aslist(t.get('actions')))]


def analyze(data):
    """Separate configured candidates, recorded execution, and visible windows.

    Scheduler PID + timestamp identifies a root only within two seconds.
    Descendants use Sysmon ProcessGuid, never a bare reused PID.
    Neither process creation nor Hidden flags prove what was visible onscreen.
    """
    result = {'bootTime': data.get('bootTime'), 'collectedAt': data.get('collectedAt'),
              'limitations': list(data.get('errors') or []), 'candidates': [],
              'executions': [], 'consoleProcesses': [],
              'windowAttributions': [],
              'visibleWindowTrace': data.get('visibleWindowTrace'),
              'verdict': 'Process/task evidence cannot by itself prove which windows were visible.'}
    visible = data.get('visibleWindowTrace')
    if visible:
        result['verdict'] = ('Visible SHOW events are recorded for the observed desktop/session. '
                             'Task attribution still requires process identity or corroborating evidence.')
        if visible.get('capped'):
            result['limitations'].append('Visible-window event capture capped at 10000 records.')
    for task in aslist(data.get('tasks')):
        actions = aslist(task.get('actions'))
        if any(_base(a.get('execute')) in CONSOLES for a in actions):
            result['candidates'].append({
                'task': (task.get('path') or '') + (task.get('name') or ''),
                'logonType': task.get('logonType'), 'hiddenSetting': task.get('hidden'),
                'triggers': task.get('triggers'), 'lastRun': task.get('lastRun'),
                'lastResult': task.get('lastResult'),
                'images': [a.get('execute') for a in actions]})
    events = {}
    for window in aslist(data.get('windows')):
        label = window.get('label'); channel = window.get('channel', '')
        if window.get('status') != 'ok':
            result['limitations'].append(f"{label}: {channel}: {window.get('status')}: {window.get('error', '')}")
        if window.get('capped'):
            result['limitations'].append(f"{label}: {channel}: query capped; older matching events omitted")
        oldest, start = _stamp(window.get('oldestTime')), _stamp(window.get('start'))
        if oldest is not None and start is not None and oldest > start:
            result['limitations'].append(f"{label}: {channel}: retained log begins after requested start; history incomplete")
        for event in aslist(window.get('events')):
            key = (channel, event.get('recordId'))
            if event.get('recordId') is None:
                key += (event.get('id'), event.get('time'), json.dumps(event.get('data'), sort_keys=True))
            events[key] = dict(event, channel=channel)
    procs = [e for e in events.values() if 'Sysmon' in e['channel'] and e.get('id') == 1]
    for window in (visible or {}).get('windows') or []:
        when = _stamp(window.get('time'))
        matches = [p for p in procs
                   if str(p['data'].get('ProcessId')) == str(window.get('pid'))
                   and when is not None and _stamp(p.get('time')) is not None
                   and 0 <= when - _stamp(p['time']) <= 2]
        if len(matches) != 1:
            continue
        proc = matches[0]
        tasks = _configured_tasks(proc['data'], aslist(data.get('tasks')))
        result['windowAttributions'].append({
            'windowTime': window.get('time'), 'windowClass': window.get('windowClass'),
            'pid': window.get('pid'), 'image': proc['data'].get('Image'),
            'processGuid': proc['data'].get('ProcessGuid'), 'processRecordId': proc.get('recordId'),
            'matchingConfiguredTasks': tasks,
            'confidence': 'window PID and process creation time; task command match, not scheduler execution proof'})
    for event in sorted(procs, key=lambda e: e.get('time', '')):
        d = event.get('data') or {}
        if _base(d.get('Image')) in CONSOLES:
            result['consoleProcesses'].append({'time': event.get('time'), 'recordId': event.get('recordId'),
                'image': d.get('Image'), 'pid': d.get('ProcessId'), 'guid': d.get('ProcessGuid'),
                'parent': d.get('ParentImage'), 'parentGuid': d.get('ParentProcessGuid')})
    for event in events.values():
        if 'TaskScheduler' not in event['channel'] or event.get('id') != 129:
            continue
        d = event.get('data') or {}; when = _stamp(event.get('time'))
        pid = d.get('ProcessID') or d.get('ProcessId')
        matches = [p for p in procs if pid and str((p.get('data') or {}).get('ProcessId')) == str(pid)
                   and when is not None and _stamp(p.get('time')) is not None
                   and abs(_stamp(p['time']) - when) <= 2]
        entry = {'task': d.get('TaskName'), 'time': event.get('time'),
                 'recordId': event.get('recordId'), 'pid': pid, 'path': d.get('Path'),
                 'correlation': 'unmatched', 'descendants': []}
        if len(matches) == 1 and (matches[0].get('data') or {}).get('ProcessGuid') not in UNKNOWN_GUIDS | {None}:
            root = matches[0]; guid = root['data']['ProcessGuid']
            entry.update(correlation='pid-and-time', processGuid=guid, processRecordId=root.get('recordId'))
            family = {guid}; children = []
            for _ in range(16):
                added = [p for p in procs if p['data'].get('ParentProcessGuid') in family
                         and p['data'].get('ProcessGuid') not in UNKNOWN_GUIDS | {None}
                         and p['data']['ProcessGuid'] not in family]
                if not added:
                    break
                children.extend(added); family.update(p['data']['ProcessGuid'] for p in added)
            entry['descendants'] = [{'image': p['data'].get('Image'), 'time': p.get('time'),
                                    'guid': p['data'].get('ProcessGuid'), 'recordId': p.get('recordId')}
                                   for p in children]
        elif len(matches) > 1:
            entry['correlation'] = 'ambiguous'
        result['executions'].append(entry)
    result['executions'].sort(key=lambda e: e.get('time', ''))
    return result


def collect():
    script = win_script('startup_trace.ps1').read_text()
    data = ps_json(script, timeout=180)
    if not isinstance(data, dict):
        return {'errors': ['Windows bridge returned no usable trace; attribution unavailable.']}
    return data


def capture_windows(seconds=360):
    """Observe this Windows session for at most ten minutes, then unhook."""
    if not 1 <= seconds <= 600:
        raise ValueError('seconds must be between 1 and 600')
    script = win_script('window_trace.ps1').read_text()
    return ps_json(script.replace('__SECONDS__', str(int(seconds))), timeout=seconds + 45)


def save(data, name):
    directory = case_dir(name)
    summary = analyze(data)
    manifest = Manifest(directory)
    for name, payload in (('startup-trace.json', data), ('startup-summary.json', summary)):
        path = os.path.join(directory, name)
        # Exclusive creation: never silently overwrite an earlier evidence file.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(payload, stream, indent=2)
        manifest.record(name, sha256_file(path), os.path.getsize(path),
                        source='Windows event logs and scheduled task inventory', kind='startup-trace')
        manifest.save()
    return directory, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', default='startup-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    parser.add_argument('--watch-seconds', type=int, choices=range(1, 601), metavar='1..600',
                        help='observe visible top-level windows for this many seconds before tracing logs')
    args = parser.parse_args(argv)
    visible = capture_windows(args.watch_seconds) if args.watch_seconds else None
    data = collect()
    if args.watch_seconds:
        data['visibleWindowTrace'] = visible
        if visible is None:
            data.setdefault('errors', []).append('Visible-window observer returned no data.')
    directory, result = save(data, args.case)
    print(json.dumps({'evidence': directory, 'limitations': result['limitations'],
                      'candidates': len(result['candidates']),
                      'taskExecutions': len(result['executions']),
                      'consoleProcesses': len(result['consoleProcesses']),
                      'visibleWindows': len((visible or {}).get('windows') or []),
                      'windowTaskMatches': sorted({task for entry in result['windowAttributions']
                                                  for task in entry['matchingConfiguredTasks']}),
                      'verdict': result['verdict']}, indent=2))


if __name__ == '__main__':
    main()
