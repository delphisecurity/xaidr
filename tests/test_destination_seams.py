"""S10 · destination policy, and S11 · blocked-URL provider.

Both hang off `ProtectedHttpClient._check_destination`, which is the one place
open decides a request must not leave the process. Neither seam may WIDEN that
decision — an extension can stop a destination the operator did not list, and it
can add to the blocklist, but it cannot let a destination past that open would
have stopped. That asymmetry is the whole contract and it is what the
contract-error tests below pin.

S10 also closes a gap #5 left open. That PR added
`except (DelphiBlockedError, _VerdictStrengthenedError)` to `_check_destination`
and reported honestly that the clause was UNREACHABLE — nothing on that path
could raise it, so its sabotage proved nothing. S10 puts extension code inside
that function for the first time, and the contract error below is what makes the
clause live.
"""

import logging

import pytest

httpx = pytest.importorskip("httpx")

from xaidr import Sensor, SensorExtension                       # noqa: E402
from xaidr.types import DelphiBlockedError, ScanResult          # noqa: E402


def _blocking(category="ext_destination"):
    return ScanResult(action="blocked", score=1.0, category=category,
                      rules=["EXT_DEST_BLOCKED"])


class _DestBlocker(SensorExtension):
    name = "dest-blocker"

    def __init__(self, host_to_block="evil.example", result=None):
        self._host = host_to_block
        self._result = result
        self.seen = []

    def destination_policy(self, dest):
        self.seen.append(dest)
        if dest.host == self._host:
            return self._result if self._result is not None else _blocking()
        return None


class _UrlProvider(SensorExtension):
    name = "url-provider"

    def __init__(self, *lists):
        self._lists = list(lists)
        self.calls = 0

    def blocked_urls(self):
        self.calls += 1
        idx = min(self.calls - 1, len(self._lists) - 1)
        return self._lists[idx]


def _client(**kw):
    sensor = Sensor(agent_id="dest-test", enforcement_mode="block", **kw)
    return sensor, sensor.protect_http(httpx.Client())


# ── S10 ──────────────────────────────────────────────────────────────────────

def test_bare_sensor_consults_no_destination_policy():
    sensor, _ = _client()
    assert sensor.extensions == ()


def test_an_extension_can_block_a_destination_the_operator_did_not_list():
    ext = _DestBlocker()
    sensor, client = _client(extensions=[ext])
    with pytest.raises(DelphiBlockedError):
        client._check_destination("https://evil.example/path?token=secret")
    assert ext.seen, "the hook was never consulted"


def test_without_the_extension_the_same_destination_is_allowed():
    """The negative half."""
    _, client = _client()
    client._check_destination("https://evil.example/path")   # must not raise


def test_a_declining_extension_leaves_the_destination_alone():
    ext = _DestBlocker(host_to_block="other.example")
    _, client = _client(extensions=[ext])
    client._check_destination("https://evil.example/path")
    assert ext.seen, "declining still means it was asked"


def test_the_view_is_host_only_and_never_carries_the_url_or_query():
    ext = _DestBlocker(host_to_block="nope.example")
    _, client = _client(extensions=[ext])
    client._check_destination("https://evil.example/secret/path?token=abc123")
    (view,) = ext.seen
    blob = repr(view)
    assert view.host == "evil.example"
    assert "token" not in blob and "abc123" not in blob
    assert "/secret/path" not in blob


def test_the_hook_runs_BEFORE_the_operator_blocklist():
    """Ordering. If the blocklist ran first, the extension would never see a
    destination the operator had already listed."""
    ext = _DestBlocker(host_to_block="evil.example")
    _, client = _client(blocked_urls=["evil.example"], extensions=[ext])
    with pytest.raises(DelphiBlockedError):
        client._check_destination("https://evil.example/x")
    assert ext.seen, "the blocklist short-circuited before the extension"


def test_a_non_blocking_return_is_a_contract_error():
    """The hook may return a block or None. Anything else would short-circuit
    the operator blocklist below and let a destination past that open would
    have stopped."""
    ext = _DestBlocker(result=ScanResult(action="allowed", score=0.0))
    _, client = _client(blocked_urls=["evil.example"], extensions=[ext])
    with pytest.raises(RuntimeError, match="destination_policy"):
        client._check_destination("https://evil.example/x")


def test_a_contract_error_is_NOT_failed_open():
    """This is the clause #5 could not prove. `_check_destination` fails open on
    any unexpected exception; a contract violation must be re-raised instead of
    becoming a silently permitted destination."""
    ext = _DestBlocker(result=ScanResult(action="flagged", score=0.5))
    _, client = _client(extensions=[ext])
    with pytest.raises(RuntimeError):
        client._check_destination("https://evil.example/x")


def test_a_raising_extension_is_fail_safe_and_does_not_block(caplog):
    """An ENVIRONMENT fault is different from a contract violation: the scan
    proceeds on open's own decision."""
    class Broken(SensorExtension):
        name = "broken-dest"

        def destination_policy(self, dest):
            raise RuntimeError("policy service down")

    _, client = _client(extensions=[Broken()])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        client._check_destination("https://ordinary.example/x")
    assert any("broken-dest" in r.getMessage() for r in caplog.records)


def test_a_broken_extension_does_not_disable_the_operator_blocklist():
    class Broken(SensorExtension):
        name = "broken-dest-2"

        def destination_policy(self, dest):
            raise RuntimeError("down")

    _, client = _client(blocked_urls=["evil.example"], extensions=[Broken()])
    with pytest.raises(DelphiBlockedError):
        client._check_destination("https://evil.example/x")


# ── S11 ──────────────────────────────────────────────────────────────────────

def test_bare_sensor_effective_list_is_its_own_list():
    sensor, _ = _client(blocked_urls=["a.example"])
    assert sensor.effective_blocked_urls() == ["a.example"]


def test_an_extension_adds_to_the_blocklist():
    sensor, client = _client(extensions=[_UrlProvider(["ext.example"])])
    assert "ext.example" in sensor.effective_blocked_urls()
    with pytest.raises(DelphiBlockedError):
        client._check_destination("https://ext.example/x")


def test_without_the_extension_the_same_url_is_allowed():
    _, client = _client()
    client._check_destination("https://ext.example/x")


def test_a_provider_whose_list_CHANGES_is_seen_on_the_second_call():
    """The staleness test. `unblock_urls` rebinds `_blocked_urls`, so anything
    that cached a reference would go stale; the provider is read fresh."""
    provider = _UrlProvider([], ["late.example"])
    sensor, client = _client(extensions=[provider])
    # First read: provider returns nothing.
    client._check_destination("https://late.example/x")
    # Second read: provider now lists it.
    with pytest.raises(DelphiBlockedError):
        client._check_destination("https://late.example/x")
    assert provider.calls >= 2, "the provider must be consulted on every check"


def test_the_effective_list_is_not_cached_between_calls():
    provider = _UrlProvider(["one.example"], ["two.example"])
    sensor, _ = _client(extensions=[provider])
    first = sensor.effective_blocked_urls()
    second = sensor.effective_blocked_urls()
    assert first != second, "a cached list would return the same answer twice"


def test_unblock_urls_still_works_composed_with_a_provider():
    """`unblock_urls` REBINDS the operator list. The extension's contribution
    must survive that, and the operator's removal must still take effect."""
    provider = _UrlProvider(["ext.example"])
    sensor, _ = _client(blocked_urls=["op.example"], extensions=[provider])
    assert set(sensor.effective_blocked_urls()) == {"op.example", "ext.example"}
    sensor.unblock_urls(["op.example"])
    effective = sensor.effective_blocked_urls()
    assert "op.example" not in effective, "operator removal must take effect"
    assert "ext.example" in effective, (
        "the extension's contribution must survive the rebind — this is the "
        "exact staleness a cached reference would produce"
    )


def test_an_operator_cannot_unblock_an_extensions_url():
    """unblock_urls edits the OPERATOR list only. An extension's list is the
    extension's; letting the operator delete from it would make the enterprise
    control removable by the thing it is meant to constrain."""
    sensor, _ = _client(extensions=[_UrlProvider(["ext.example"])])
    sensor.unblock_urls(["ext.example"])
    assert "ext.example" in sensor.effective_blocked_urls()


def test_a_raising_provider_is_fail_safe_and_keeps_the_operator_list(caplog):
    class Broken(SensorExtension):
        name = "broken-urls"

        def blocked_urls(self):
            raise RuntimeError("feed down")

    sensor, _ = _client(blocked_urls=["op.example"], extensions=[Broken()])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        assert sensor.effective_blocked_urls() == ["op.example"]
    assert any("broken-urls" in r.getMessage() for r in caplog.records)


def test_the_returned_list_is_a_copy():
    sensor, _ = _client(blocked_urls=["op.example"])
    sensor.effective_blocked_urls().append("injected.example")
    assert "injected.example" not in sensor.effective_blocked_urls()
