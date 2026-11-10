"""S12 · outbound egress headers, and the flag that gates provenance.

THIS FILE IS THE ZERO-MOVEMENT GATE FOR THIS SEAM, and it has to be, because
the corpus oracle cannot see it. The oracle hashes `scan()` verdicts — action,
score, category, rules — over the committed corpus. It does not make an HTTP
request and it never inspects a header, so S12 could change what every outbound
call discloses to every destination host and the oracle would stay byte-identical
at the same sha256 it has had for four PRs. A green oracle here would mean
"nothing this gate can see moved", which is not the same sentence as "nothing
moved".

So the flag-off half below is not a nicety. It is the only thing standing between
"consolidated five call sites into one" and "silently started announcing the
agent id, a correlation id and the delegation chain to every host this process
talks to".

THE ASYMMETRY IS DELIBERATE. Before this seam, POST/PUT/PATCH wrote
`X-Delphi-Source-Agent` and GET/DELETE wrote no header at all. With the flag off
that is preserved exactly — GET and DELETE still send nothing. Making them start
sending the agent id would be a disclosure change, and it is the same change the
flag exists to gate; consolidating call sites is not a licence to make it.
With the flag ON every verb carries the full set, because a deployer who asked
for the chain to be visible should not find a GET-shaped hole in it.
"""

import pytest

httpx = pytest.importorskip("httpx")

from xaidr import Sensor, begin_flow, clear_flow                 # noqa: E402

VERBS = ("post", "put", "patch", "get", "delete")
BODY_VERBS = ("post", "put", "patch")
BARE_VERBS = ("get", "delete")

SOURCE_AGENT = "X-Delphi-Source-Agent"
#: Exactly what `provenance_chain.inject_context` writes. Spelled out rather
#: than imported so that a change to the writer has to be acknowledged here.
PROVENANCE_HEADERS = frozenset({
    "traceparent",
    "x-openA2A-correlation",
    "x-openA2A-chain",
    "x-openA2A-tiers",
})


class _Capture:
    """Replaces the underlying httpx verbs and records the headers sent."""

    def __init__(self):
        self.seen = {}

    def bind(self, client):
        for verb in VERBS:
            setattr(client._client, verb, self._recorder(verb))
        return client

    def _recorder(self, verb):
        def call(url, **kwargs):
            self.seen[verb] = dict(kwargs.get("headers") or {})
            return httpx.Response(
                200, request=httpx.Request(verb.upper(), url))
        return call


def _drive(emit, *, caller_headers=None, with_flow=True):
    sensor = Sensor(agent_id="egress-test", emit_provenance_headers=emit)
    client = sensor.protect_http(httpx.Client())
    cap = _Capture()
    cap.bind(client)
    clear_flow()
    if with_flow:
        begin_flow(principal="alice")
    extra = {"headers": caller_headers} if caller_headers else {}
    client.post("https://h.example/x", json={}, **extra)
    client.put("https://h.example/x", json={}, **extra)
    client.patch("https://h.example/x", json={}, **extra)
    client.get("https://h.example/x", **extra)
    client.delete("https://h.example/x", **extra)
    clear_flow()
    return cap.seen


# ── flag OFF: byte-identical to the tree before this seam ────────────────────

def test_off_body_verbs_send_only_the_source_agent():
    seen = _drive(False)
    for verb in BODY_VERBS:
        assert set(seen[verb]) == {SOURCE_AGENT}, (
            f"{verb} sent {sorted(seen[verb])}; before S12 it sent exactly "
            f"{SOURCE_AGENT}"
        )
        assert seen[verb][SOURCE_AGENT] == "egress-test"


def test_off_get_and_delete_send_NO_headers():
    """The half that would break first if consolidation leaked a disclosure.

    GET and DELETE wrote no header at all before this seam. Them starting to
    announce the agent id is exactly the unrequested disclosure the flag gates.
    """
    seen = _drive(False)
    for verb in BARE_VERBS:
        assert seen[verb] == {}, (
            f"{verb} sent {sorted(seen[verb])} with the provenance flag OFF; "
            "before S12 it sent nothing at all"
        )


def test_off_no_provenance_header_appears_on_any_verb():
    seen = _drive(False)
    for verb in VERBS:
        leaked = PROVENANCE_HEADERS & {k.lower() for k in seen[verb]} | (
            PROVENANCE_HEADERS & set(seen[verb]))
        assert not leaked, f"{verb} leaked provenance headers {sorted(leaked)}"


def test_off_is_the_default():
    """Nobody opts out; the disclosure is opt-IN."""
    assert Sensor(agent_id="default-probe").emit_provenance_headers is False


def test_off_preserves_caller_supplied_headers():
    seen = _drive(False, caller_headers={"X-Caller": "mine"})
    for verb in VERBS:
        assert seen[verb].get("X-Caller") == "mine"


# ── flag ON: every verb carries the full set ─────────────────────────────────

def test_on_every_verb_carries_source_agent_and_all_four_provenance_headers():
    seen = _drive(True)
    for verb in VERBS:
        sent = set(seen[verb])
        assert SOURCE_AGENT in sent, f"{verb} lost {SOURCE_AGENT}"
        missing = PROVENANCE_HEADERS - sent
        assert not missing, f"{verb} is missing {sorted(missing)}"


def test_on_get_and_delete_are_not_a_hole_in_the_chain():
    """The specific regression the consolidation exists to prevent: a deployer
    who turned the chain on must not find two verbs quietly omitting it."""
    seen = _drive(True)
    for verb in BARE_VERBS:
        assert PROVENANCE_HEADERS <= set(seen[verb])


def test_on_the_chain_header_carries_the_flow():
    seen = _drive(True)
    corr = {seen[v]["x-openA2A-correlation"] for v in VERBS}
    assert all(c for c in corr), "correlation id must be populated"
    assert seen["get"]["traceparent"].startswith("00-")


def test_on_preserves_caller_supplied_headers():
    seen = _drive(True, caller_headers={"X-Caller": "mine"})
    for verb in VERBS:
        assert seen[verb].get("X-Caller") == "mine"


def test_on_does_not_change_the_source_agent_value():
    seen = _drive(True)
    for verb in VERBS:
        assert seen[verb][SOURCE_AGENT] == "egress-test"


# ── the consolidation itself ─────────────────────────────────────────────────

def test_all_five_verbs_route_through_one_helper():
    """S12's grep tripwire, as a test. Five call sites that can drift are what
    this seam exists to remove; asserting the source keeps the claim honest
    even if a future verb is added without one."""
    import inspect

    from xaidr.sensor import ProtectedHttpClient

    shared = inspect.getsource(ProtectedHttpClient._body_verb)
    assert "_egress_headers(" in shared, "_body_verb does not route through _egress_headers"
    for verb in VERBS:
        src = inspect.getsource(getattr(ProtectedHttpClient, verb))
        # The body verbs share _body_verb (scan, headers, attestation, send, in
        # that order); GET and DELETE call the helper themselves.
        assert "_egress_headers(" in src or "_body_verb(" in src, (
            f"{verb} does not route through _egress_headers — S12's whole "
            "claim is that there is exactly one place a header is written"
        )


def test_no_verb_writes_the_source_agent_header_directly():
    """The other half of the tripwire: consolidation is only real if the old
    direct writes are gone."""
    import inspect

    from xaidr.sensor import ProtectedHttpClient

    for name in VERBS + ("_body_verb",):
        src = inspect.getsource(getattr(ProtectedHttpClient, name))
        assert SOURCE_AGENT not in src, (
            f"{name} still writes {SOURCE_AGENT} directly instead of going "
            "through the helper"
        )


# ── S12 follow-up (#14): extension outbound_headers merging ──────────────────
#
# The merge is ADD-ONLY. An extension may contribute new headers; it may never
# remove or overwrite one that is already open — not the sensor's, not the
# caller's, not another extension's. A collision is logged once, then the
# extension's header is dropped; the request always goes out.

from xaidr.extensions import DestinationView, SensorExtension  # noqa: E402


class _AddHeaders(SensorExtension):
    name = "acme-add"

    def __init__(self, headers):
        self._headers = dict(headers)
        self.seen_dests = []

    def outbound_headers(self, dest):
        self.seen_dests.append(dest)
        return dict(self._headers)


class _OverwriteAgent(SensorExtension):
    """Tries to overwrite X-Delphi-Source-Agent — the misattribution #14 is
    about."""

    name = "acme-overwrite"

    def outbound_headers(self, dest):
        return {"X-Delphi-Source-Agent": "mallory"}


class _OverwriteAgentLower(SensorExtension):
    """Same attack through the case-insensitivity door."""

    name = "acme-overwrite-lower"

    def outbound_headers(self, dest):
        return {"x-delphi-source-agent": "mallory"}


class _OverwriteTraceparent(SensorExtension):
    name = "acme-overwrite-trace"

    def outbound_headers(self, dest):
        return {"traceparent": "00-deadbeef-deadbeef-00"}


class _ThrowingHeaders(SensorExtension):
    name = "acme-throw"

    def outbound_headers(self, dest):
        raise RuntimeError("header backend down")


def _drive_with(emit, extensions, *, caller_headers=None):
    sensor = Sensor(agent_id="egress-test", emit_provenance_headers=emit,
                    extensions=extensions)
    client = sensor.protect_http(httpx.Client())
    cap = _Capture()
    cap.bind(client)
    clear_flow()
    begin_flow(principal="alice")
    extra = {"headers": caller_headers} if caller_headers else {}
    client.post("https://h.example/x?token=secret", json={}, **extra)
    client.get("https://h.example/x?token=secret", **extra)
    clear_flow()
    return cap.seen


def test_extension_added_headers_ride_on_every_verb():
    ext = _AddHeaders({"X-Acme-Tenant": "t-1"})
    seen = _drive_with(False, [ext])
    for verb in ("post", "get"):
        assert seen[verb]["X-Acme-Tenant"] == "t-1"
    # The sensor's own headers are untouched by the merge.
    assert seen["post"][SOURCE_AGENT] == "egress-test"


def test_extension_sees_a_host_only_destination_view():
    ext = _AddHeaders({"X-Acme-Tenant": "t-1"})
    _drive_with(False, [ext])
    assert ext.seen_dests, "outbound_headers was never called"
    for dest in ext.seen_dests:
        assert isinstance(dest, DestinationView)
        assert dest.host == "h.example"
        # HOST ONLY — the query string must not cross the seam.
        assert "secret" not in repr(dest), (
            f"destination view leaked the URL/query: {dest!r}")


def test_extension_cannot_overwrite_the_source_agent_header():
    seen = _drive_with(False, [_OverwriteAgent()])
    assert seen["post"][SOURCE_AGENT] == "egress-test", (
        "extension overwrote X-Delphi-Source-Agent — the misattribution #14 "
        "exists to prevent")


def test_collision_check_is_case_insensitive():
    seen = _drive_with(False, [_OverwriteAgentLower()])
    assert seen["post"][SOURCE_AGENT] == "egress-test"
    assert "x-delphi-source-agent" not in seen["post"]


def test_extension_cannot_overwrite_provenance_headers():
    seen = _drive_with(True, [_OverwriteTraceparent()])
    assert seen["post"]["traceparent"].startswith("00-")
    assert "deadbeef" not in seen["post"]["traceparent"]


def test_collision_is_logged_once_then_the_request_goes_out(caplog):
    import logging

    sensor = Sensor(agent_id="egress-test", extensions=[_OverwriteAgent()])
    client = sensor.protect_http(httpx.Client())
    cap = _Capture()
    cap.bind(client)
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        for _ in range(3):
            client.post("https://h.example/x", json={})
    hits = [r for r in caplog.records
            if "acme-overwrite" in r.getMessage()
            and "outbound_headers" in r.getMessage()]
    assert len(hits) == 1, (
        f"expected exactly one collision log line, got {len(hits)}")
    # Degrade, not fail: all three requests went out with the sensor's header.
    assert cap.seen["post"][SOURCE_AGENT] == "egress-test"


def test_a_throwing_extension_does_not_break_egress():
    seen = _drive_with(False, [_ThrowingHeaders(),
                               _AddHeaders({"X-Acme-Tenant": "t-1"})])
    assert seen["post"]["X-Acme-Tenant"] == "t-1"
    assert seen["post"][SOURCE_AGENT] == "egress-test"


def test_first_extension_wins_on_extension_vs_extension_collision():
    seen = _drive_with(False, [_AddHeaders({"X-Acme": "first"}),
                               _AddHeaders({"X-Acme": "second"})])
    assert seen["post"]["X-Acme"] == "first"


def test_caller_supplied_headers_beat_extensions():
    seen = _drive_with(False, [_AddHeaders({"X-Caller": "extension"})],
                       caller_headers={"X-Caller": "mine"})
    assert seen["post"]["X-Caller"] == "mine"


def test_no_extensions_means_no_view_is_built():
    """The merge path must not cost a parse when there is nothing to merge."""
    import xaidr.sensor as sensor_mod

    calls = []
    orig = sensor_mod.ProtectedHttpClient._extract_host
    sensor_mod.ProtectedHttpClient._extract_host = lambda self, url: (
        calls.append(url) or orig(self, url))
    try:
        _drive(False)  # the no-extension driver from the S12 section
    finally:
        sensor_mod.ProtectedHttpClient._extract_host = orig
    assert calls == [], (
        f"_egress_headers parsed hosts with no extensions attached: {calls}")


# ── M0 (1.22.0): a fault in outbound_headers() never reaches the host ────────
#
# Two shapes raised INTO the host's request on the merge as first written: a
# truthy non-Mapping return (``.items()`` sat outside the ``try``) and a non-str
# header name (``name.lower()`` sat outside it too). The S12 rule is that a fault
# in this hook drops that extension's headers, is logged once, and the request
# goes out. Under ``fail_closed=("controls",)`` the fault travels the verdict
# path: monitor records it and proceeds, block refuses with DelphiBlockedError.
# A raw ``FailClosedError`` is never what the host sees.

import logging                                                      # noqa: E402

from xaidr import DelphiBlockedError                                # noqa: E402


class _BadReturn(SensorExtension):
    """Returns a truthy value that is not a Mapping."""

    name = "acme-bad-return"

    def __init__(self, value):
        self._value = value

    def outbound_headers(self, dest):
        return self._value


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _post_once(sensor):
    client = sensor.protect_http(httpx.Client())
    cap = _Capture()
    cap.bind(client)
    client.post("https://h.example/x", json={})
    return cap.seen["post"]


@pytest.mark.parametrize("bad", [
    "x-acme-tenant: t-1",            # a str: truthy, no .items()
    (("x-acme-tenant", "t-1"),),     # a tuple of pairs: truthy, no .items()
    42,                              # an int
    {1: "t-1"},                      # a Mapping with a non-str key: no .lower()
    {"x-acme-tenant": 7},            # a Mapping with a non-str value
], ids=["str", "tuple", "int", "int-key", "int-value"])
def test_outbound_headers_bad_return_never_reaches_host(bad, caplog):
    sensor = Sensor(agent_id="egress-test",
                    extensions=[_BadReturn(bad),
                                _AddHeaders({"X-Acme-Other": "ok"})])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        try:
            seen = _post_once(sensor)
        except Exception as exc:   # pragma: no cover - the defect under test
            pytest.fail(
                "an extension's malformed outbound_headers return raised into "
                f"the host's request: {type(exc).__name__}")
    # The request went out, with the sensor's header and the next extension's.
    assert seen[SOURCE_AGENT] == "egress-test"
    assert seen["X-Acme-Other"] == "ok"
    # Nothing from the malformed return landed.
    assert not any(k.lower() == "x-acme-tenant" for k in seen), seen
    hits = [r for r in caplog.records
            if "acme-bad-return" in r.getMessage()
            and "outbound_headers" in r.getMessage()]
    assert len(hits) == 1, f"expected one fault line, got {len(hits)}"


def test_outbound_headers_bad_return_is_logged_once_per_sensor(caplog):
    sensor = Sensor(agent_id="egress-test", extensions=[_BadReturn(42)])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        for _ in range(3):
            _post_once(sensor)
    hits = [r for r in caplog.records if "acme-bad-return" in r.getMessage()]
    assert len(hits) == 1, f"expected one fault line over three requests, got {len(hits)}"


def test_outbound_headers_fault_under_fail_closed_monitor_proceeds():
    """``controls`` closed, monitor: the fault is a verdict, the verdict is
    softened to flagged, and the request goes out. No raw FailClosedError."""
    sink = _Sink()
    sensor = Sensor(agent_id="egress-test", enforcement_mode="monitor",
                    fail_closed=("controls",), extensions=[_ThrowingHeaders()],
                    reporter=sink)
    sensor._telemetry_sink = sink
    try:
        seen = _post_once(sensor)
    except Exception as exc:   # pragma: no cover - the defect under test
        pytest.fail(
            "a fail-closed fault in outbound_headers raised a raw "
            f"{type(exc).__name__} into a MONITOR sensor's host request")
    assert seen[SOURCE_AGENT] == "egress-test"
    # The refusal that monitor softened still left its record: one
    # fail_closed event naming the group. Telemetry keeps the TRUE verdict
    # (``_emit_fail_closed`` runs before the downgrade), with the mode beside
    # it, so the operator sees what the posture would have refused.
    sensor.flush()
    fc = [e for e in sensor._telemetry_sink.events
          if e["data"].get("failClosedGroup") == "controls"]
    assert len(fc) == 1, f"expected one fail_closed event, got {len(fc)}"
    assert fc[0]["data"]["action"] == "blocked"
    assert fc[0]["data"]["enforcementMode"] == "monitor"


def test_outbound_headers_fault_under_fail_closed_block_refuses_in_band():
    """``controls`` closed, block: the request is refused with the one exception
    type this boundary already raises, never with FailClosedError itself."""
    from xaidr.failclosed import FailClosedError

    sensor = Sensor(agent_id="egress-test", enforcement_mode="block",
                    fail_closed=("controls",), extensions=[_ThrowingHeaders()])
    client = sensor.protect_http(httpx.Client())
    cap = _Capture()
    cap.bind(client)
    with pytest.raises(DelphiBlockedError) as exc:
        client.post("https://h.example/x", json={})
    assert exc.value.result.action == "blocked"
    assert exc.value.result.input_status == "fail_closed"
    assert "post" not in cap.seen, "a refused request was sent anyway"
    # GET has no body scan, and the same header merge runs on it.
    with pytest.raises(DelphiBlockedError):
        client.get("https://h.example/x")
    assert "get" not in cap.seen
    assert FailClosedError is not DelphiBlockedError   # the type the host sees


# ── M0 review follow-ups ─────────────────────────────────────────────────────


def _send_through_real_httpx(sensor, caller_headers=None):
    """A real httpx request build and send, through MockTransport. ``_Capture``
    replaces the verbs, so it never reaches ``build_request``, where a header
    outside ASCII raises."""
    got = {}

    def handler(request):
        got["headers"] = dict(request.headers)
        return httpx.Response(200, json={})

    client = sensor.protect_http(httpx.Client(transport=httpx.MockTransport(handler)))
    kw = {"headers": caller_headers} if caller_headers else {}
    client.post("https://h.example/x", json={}, **kw)
    return got["headers"]


@pytest.mark.parametrize("value", ["caf\u00e9", "a\r\nInjected: 1", "tab\there"],
                         ids=["non-ascii", "crlf", "tab"])
def test_a_header_value_outside_printable_ascii_never_reaches_httpx(value, caplog):
    sensor = Sensor(agent_id="egress-test",
                    extensions=[_AddHeaders({"X-Acme-Bad": value}),
                                _AddHeaders({"X-Acme-Other": "ok"})])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        try:
            headers = _send_through_real_httpx(sensor)
        except Exception as exc:   # pragma: no cover - the defect under test
            pytest.fail(
                "an extension's header value outside printable ASCII raised "
                f"{type(exc).__name__} out of the host's send()")
    assert "x-acme-bad" not in headers
    assert headers["x-acme-other"] == "ok"
    assert headers["x-delphi-source-agent"] == "egress-test"


def test_a_header_name_that_is_not_a_token_never_reaches_httpx():
    sensor = Sensor(agent_id="egress-test",
                    extensions=[_AddHeaders({"X Acme Spaced": "v"}),
                                _AddHeaders({"X-Acme-Other": "ok"})])
    headers = _send_through_real_httpx(sensor)
    assert not any("spaced" in k for k in headers)
    assert headers["x-acme-other"] == "ok"


def test_collision_under_fail_closed_block_still_sends_the_request():
    """A collision DEGRADES. It is never a control fault, so ``controls`` closed
    plus block mode drops the header and sends the request."""
    sensor = Sensor(agent_id="egress-test", enforcement_mode="block",
                    fail_closed=("controls",), extensions=[_OverwriteAgent()])
    headers = _send_through_real_httpx(sensor)
    assert headers["x-delphi-source-agent"] == "egress-test"


def test_a_bytes_caller_header_name_is_still_protected_from_an_extension():
    sensor = Sensor(agent_id="egress-test",
                    extensions=[_AddHeaders({"authorization": "ext"})])
    headers = _send_through_real_httpx(sensor, caller_headers={b"Authorization": b"caller"})
    assert headers["authorization"] == "caller"


def test_fault_in_a_non_last_extension_under_fail_closed_block_refuses():
    sensor = Sensor(agent_id="egress-test", enforcement_mode="block",
                    fail_closed=("controls",),
                    extensions=[_ThrowingHeaders(), _AddHeaders({"X-Acme-Other": "ok"})])
    with pytest.raises(DelphiBlockedError):
        _send_through_real_httpx(sensor)


@pytest.mark.xfail(strict=True, reason=(
    "found, not fixed, in the M0 review (pre-existing on main): _check_destination "
    "raises DelphiBlockedError on a fail-closed fault even after monitor softened "
    "the verdict to flagged, so a monitor sensor interrupts the request there "
    "while the header merge does not"))
def test_destination_policy_fault_under_fail_closed_monitor_proceeds():
    class _RaisingDestination(SensorExtension):
        name = "acme-dest-raise"

        def destination_policy(self, dest):
            raise RuntimeError("down")

    sensor = Sensor(agent_id="egress-test", enforcement_mode="monitor",
                    fail_closed=("controls",), extensions=[_RaisingDestination()])
    headers = _send_through_real_httpx(sensor)
    assert headers["x-delphi-source-agent"] == "egress-test"


@pytest.mark.parametrize("value", ["v ", " v", "v\t"], ids=["trailing", "leading", "tab"])
def test_an_s12_value_with_edge_whitespace_is_dropped_before_the_transport(value):
    sensor = Sensor(agent_id="egress-test",
                    extensions=[_AddHeaders({"X-Acme-Bad": value}),
                                _AddHeaders({"X-Acme-Other": "ok"})])
    headers = _send_through_real_httpx(sensor)
    assert "x-acme-bad" not in headers
    assert headers["x-acme-other"] == "ok"
