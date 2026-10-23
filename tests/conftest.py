"""
Root pytest configuration.

Marks a small set of known, pre-existing test failures as xfail so CI gives
a meaningful signal (red = this PR broke something) instead of always being
red regardless of what changed, for whatever debt doesn't get fixed right
away. strict=True means each entry must still genuinely fail - if one starts
passing (e.g. someone fixes the underlying bug without removing it from this
list), pytest reports it as XPASS and the run fails, as a nudge to remove
that entry.

Empty as of the pre-existing-failures triage pass: the 7 failures this
mechanism originally isolated (TheHive priority casing, local_tip's error
message convention, and OpenCTI's GraphQL query/endpoint drift) have all
been fixed at the source. Left in place for the next time something needs
the same treatment.
"""

from __future__ import annotations

import pytest

_KNOWN_PRE_EXISTING_FAILURES: dict[str, str] = {}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        reason = _KNOWN_PRE_EXISTING_FAILURES.get(item.nodeid)
        if reason:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=True))
