import pytest

# Import the real probe modules once, before any snapshot is taken, so the four
# shipped probes are present in every test's baseline registry.
import asi_scan.probes  # noqa: F401
from asi_scan.probes.base import REGISTRY


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Snapshot the global probe registry and restore it after each test.

    Probes registered inside a test (via the ``demo_probe`` / ``engine_probe``
    fixtures) are removed on teardown, so they cannot leak into other tests and
    silently change what a later ``scan()`` runs.
    """
    snapshot = dict(REGISTRY)
    try:
        yield
    finally:
        REGISTRY.clear()
        REGISTRY.update(snapshot)
