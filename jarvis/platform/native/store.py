"""Validation of the native sensor's immutable batch files.

A batch is untrusted input until it passes here: the spool directory is
readable by the user account, and a malformed or forged file must fail loudly
rather than advance a cursor. Storage lives in `jarvis.core.eventlog`.
"""

from datetime import datetime

MAX_BATCH_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 500


class BatchError(ValueError):
    pass


def _text(value, name, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BatchError('invalid ' + name)
    return value


def validate(batch):
    if not isinstance(batch, dict) or batch.get('schema') not in (1, 2):
        raise BatchError('unsupported schema')
    for name in ('sensor_id', 'host_id', 'channel', 'generation', 'created_at'):
        _text(batch.get(name), name)
    for name in ('device_id', 'boot_id'):
        if batch.get(name) is not None:
            _text(batch[name], name, 128)
    sequence = batch.get('sequence')
    if type(sequence) is not int or sequence < 1 or sequence > 2**63 - 1:
        raise BatchError('invalid sequence')
    if batch.get('previous_sequence') != sequence - 1:
        raise BatchError('invalid previous sequence')
    if batch.get('status') not in ('complete', 'partial', 'unavailable'):
        raise BatchError('invalid status')
    if not isinstance(batch.get('bookmark'), str):
        raise BatchError('invalid bookmark')
    events = batch.get('events')
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise BatchError('invalid event batch')
    seen = set()
    for event in events:
        if not isinstance(event, dict):
            raise BatchError('invalid event')
        record = event.get('record_id')
        if type(record) is not int or not 0 < record < 2**63 or record in seen:
            raise BatchError('invalid or duplicate record ID')
        seen.add(record)
        if type(event.get('event_id')) is not int or not 0 <= event['event_id'] <= 65535:
            raise BatchError('invalid event ID')
        _text(event.get('time'), 'event time')
        if event.get('read_time') is not None:
            stamp = _text(event['read_time'], 'sensor read time', 64)
            try:
                parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            except ValueError as exc:
                raise BatchError('invalid sensor read time') from exc
            if parsed.tzinfo is None:
                raise BatchError('sensor read time lacks timezone')
        _text(event.get('xml'), 'event XML', 1024 * 1024)
        if event.get('mono_ms') is not None and (type(event['mono_ms']) is not int
                                                 or event['mono_ms'] < 0):
            raise BatchError('invalid monotonic time')
    if batch.get('gap') is not None:
        _text(batch['gap'], 'gap')
    return batch
