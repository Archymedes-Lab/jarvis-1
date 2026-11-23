"""Per-job observation status, separate from successful Python execution."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class Observation:
    failures: list = field(default_factory=list)
    successes: set = field(default_factory=set)

    @property
    def status(self):
        return 'partial' if self.failures and self.successes else 'unavailable' if self.failures else 'complete'

    @property
    def error(self):
        return '; '.join(dict.fromkeys(self.failures))[:800]


_active = ContextVar('jarvis_collection', default=None)


def failed(source, reason):
    observation = _active.get()
    if observation is not None:
        observation.failures.append(f'{source}: {reason}')


def succeeded(source):
    observation = _active.get()
    if observation is not None:
        observation.successes.add(source)


@contextmanager
def observe():
    observation = Observation()
    token = _active.set(observation)
    try:
        yield observation
    finally:
        _active.reset(token)
