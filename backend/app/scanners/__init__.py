"""Scanner adapters. Each wraps one open-source tool installed in the worker image (Phase 5).

Importing this package imports every adapter module, and each adapter registers itself with
app.scanners.registry, in the order below (the order the scanning stage runs them).
"""

from app.scanners import nmap, nuclei, testssl  # noqa: F401
