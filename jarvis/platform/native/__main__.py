import argparse
import json
from pathlib import Path

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog

from . import ingest


def main():
    parser = argparse.ArgumentParser(
        description='Ingest immutable Windows sensor batches into the event log; '
                    'never deletes source evidence.')
    parser.add_argument('spool', nargs='?', default=str(ingest.SPOOL))
    parser.add_argument('--log', default=str(DEFAULT_ROOT), help='event log directory')
    args = parser.parse_args()
    with EventLog(Path(args.log), writer=True) as log:
        result = ingest.run(log=log, spool=args.spool)
    print(json.dumps(result, indent=2, default=str))
    return 1 if any(ch['error'] for ch in result['channels']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
