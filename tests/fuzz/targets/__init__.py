"""Fuzz targets, by area. Each module exposes TARGETS, a list of engine.Target."""

MODULES = ("tests.fuzz.targets.release_gate", "tests.fuzz.targets.collectors", "tests.fuzz.targets.web")


def all_targets():
    import importlib
    out = []
    for name in MODULES:
        out += importlib.import_module(name).TARGETS
    return out
