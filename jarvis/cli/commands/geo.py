"""`jarvis geo` — device location, geofencing, and the GeoSecurity view.

    jarvis geo status                 location, confidence, zones, anomalies
    jarvis geo here LAT LON [--label "Norrsken Kigali"]
                                      set your current location yourself
    jarvis geo here --clear           forget the location you set
    jarvis geo locate                 take one native fix now (needs consent)
    jarvis geo zone add HOME LAT LON [--radius M]
    jarvis geo zone list
    jarvis geo zone rm NAME
    jarvis geo world [--refresh]      reported conflict zones and distance to them

Locations you set are user-asserted ground truth, labelled as such and never
dressed up as a GPS fix. Raw coordinates are never kept as history; JARVIS never
infers a position from your IP.
"""

import json

from jarvis.collectors.host import geo as geo_collector
from jarvis.service import geosecurity


def _coords(rest, start):
    """Parse LAT LON from positional args; -> (lat, lon) or None."""
    try:
        return float(rest[start]), float(rest[start + 1])
    except (IndexError, ValueError):
        return None


def _cmd_here(args, store):
    if args.clear:
        geo_collector.clear_manual(store)
        print("cleared the location you set; JARVIS is back to native/none")
        return 0
    coords = _coords(args.rest, 0)
    if coords is None:
        print("usage: jarvis geo here LAT LON [--label NAME]   (or --clear)")
        return 1
    try:
        m = geosecurity.set_here(store, coords[0], coords[1], args.label)
    except ValueError as exc:
        print(exc)
        return 1
    zone = geo_collector.classify(m["lat"], m["lon"], geosecurity.get_zones(store))
    print(f"location set to {m['label']} ({m['lat']:.5f}, {m['lon']:.5f})"
          + (f" — {zone}" if geosecurity.get_zones(store) else ""))
    print("user-declared; native GPS is off, so this is not independently verified.")
    return 0


def _cmd_zone(args, store):
    sub = args.rest[0] if args.rest else "list"
    if sub == "add":
        name = args.rest[1] if len(args.rest) > 1 else None
        coords = _coords(args.rest, 2)
        if not name or coords is None:
            print("usage: jarvis geo zone add NAME LAT LON [--radius M]")
            return 1
        zones = geosecurity.add_zone(store, name, coords[0], coords[1], args.radius or 200)
        print(f"trusted zone '{name}' set ({len(zones)} total)")
        return 0
    if sub == "rm":
        name = args.rest[1] if len(args.rest) > 1 else None
        if not name:
            print("usage: jarvis geo zone rm NAME")
            return 1
        geosecurity.remove_zone(store, name)
        print(f"removed zone '{name}'")
        return 0
    zones = geosecurity.get_zones(store)
    if args.json:
        print(json.dumps(zones, indent=2))
    elif not zones:
        print("no trusted zones set — add one with: jarvis geo zone add HOME LAT LON")
    else:
        for z in zones:
            print(f"  {z['name']:12} {z['lat']:.5f}, {z['lon']:.5f}  r={z['radius_m']}m")
    return 0


def cmd_geo(args, store):
    if args.action == "here":
        return _cmd_here(args, store)
    if args.action == "zone":
        return _cmd_zone(args, store)
    if args.action == "locate":
        fix = geo_collector.locate()
        print(json.dumps(fix, indent=2) if args.json else
              f"{fix.get('status')}: " + (f"{fix.get('lat'):.5f}, {fix.get('lon'):.5f} "
              f"(~{int(fix.get('accuracy_m') or 0)} m via {fix.get('source')})"
              if fix.get("status") == "ok" else fix.get("reason", "")))
        return 0 if fix.get("status") == "ok" else 1

    if args.action == "world":
        from jarvis.intel import worldwatch
        if args.refresh:
            result = worldwatch.refresh(store)
            print(f"refreshed: {result['items']} conflict reports, {result['mapped']} placed, "
                  f"{result['zones']} zones"
                  + (f"; unreachable: {', '.join(result['failed'])}" if result["failed"] else ""))
        world = worldwatch.state(store, location=geo_collector.effective(
            store, geo_collector.current(store)), trusted=geosecurity.get_zones(store))
        if args.json:
            print(json.dumps(world, indent=2, default=str))
            return 0
        age = "never collected" if world["age_s"] is None else f"{world['age_s'] // 60} min old"
        print(f"world watch: {world['counts']['reports']} conflict reports in 72 h, "
              f"{world['counts']['mapped']} placed, {len(world['zones'])} zones ({age}"
              + (", stale" if world["stale"] else "") + ")")
        for zone in world["zones"]:
            print(f"  {zone['name']}: {zone['reports']} reports from {zone['sources']} publishers")
        for anchor in world["anchors"]:
            near = anchor.get("nearest")
            if near:
                print(f"  {anchor['name']}: " + ("inside " if near["inside"]
                      else f"{near['distance_km']} km from ") + near["name"])
        print("Zones outline clusters of reports, not front lines. "
              "View: http://localhost:8787/world")
        return 0

    # status
    payload = geosecurity.state(store)
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0
    loc = payload["location"]
    conf = payload["confidence"]
    if loc.get("status") == "ok":
        via = loc.get("label") or loc.get("source")
        where = f"{loc.get('zone')} · {via}" if payload["zones"] else str(via)
        print(f"location: ok — {where}")
    else:
        print(f"location: {loc.get('status')} — {loc.get('reason', 'no position set')}")
    print(f"confidence: {int(conf['score'] * 100)}%  "
          + ", ".join(f"{s['name']} {s['weight']}" for s in conf["signals"]))
    print(f"trusted zones: {len(payload['zones'])}  "
          + ", ".join(z["name"] for z in payload["zones"]))
    for a in payload["anomalies"]:
        print(f"  [{a['severity']}] {a['kind']}: {a['detail']}")
    print(f"imagery: {payload['imagery']['provider']} "
          f"({payload['imagery']['cadence']}). Globe: http://localhost:8787/geo")
    return 0


def add_parser(sub):
    p = sub.add_parser("geo", help="device location, geofencing and the GeoSecurity globe")
    p.add_argument("action", nargs="?", default="status",
                   choices=["status", "here", "locate", "zone", "world"])
    p.add_argument("rest", nargs="*", help="here: LAT LON · zone: add NAME LAT LON | list | rm NAME")
    p.add_argument("--label", help="a name for the location you set (e.g. 'Norrsken Kigali')")
    p.add_argument("--clear", action="store_true", help="here: forget the location you set")
    p.add_argument("--radius", type=int, help="zone radius in metres (default 200)")
    p.add_argument("--refresh", action="store_true",
                   help="world: fetch the public news feeds now")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_geo)
    return p
