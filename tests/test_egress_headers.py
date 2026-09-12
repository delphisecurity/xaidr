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

    for verb in VERBS:
        src = inspect.getsource(getattr(ProtectedHttpClient, verb))
        assert "_egress_headers(" in src, (
            f"{verb} does not route through _egress_headers — S12's whole "
            "claim is that there is exactly one place a header is written"
        )


def test_no_verb_writes_the_source_agent_header_directly():
    """The other half of the tripwire: consolidation is only real if the old
    direct writes are gone."""
    import inspect

    from xaidr.sensor import ProtectedHttpClient

    for verb in VERBS:
        src = inspect.getsource(getattr(ProtectedHttpClient, verb))
        assert SOURCE_AGENT not in src, (
            f"{verb} still writes {SOURCE_AGENT} directly instead of going "
            "through the helper"
        )
