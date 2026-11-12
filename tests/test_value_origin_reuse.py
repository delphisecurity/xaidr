"""Ruling 4 (2026-10-21): one user's principal authority never reaches another
user's request on a reused thread.

A pool thread runs one job after another in ONE context, so a ledger bound by
user A's job would still be bound when user B's job runs. Each
``ThreadPoolExecutor`` work item is therefore one request (the sensor's executor
seam): the ledgers bound in it close when it ends, including one bound by a
``begin_flow()`` the host never cleared. A host that never begins a flow needs
nothing else. The seam is in tests/test_value_origin_request_scope.py too, with
``xaidr.request_scope()`` for a server loop the sensor cannot see.
"""
from __future__ import annotations

import warnings
from concurrent.futures import ThreadPoolExecutor

import xaidr

AUTHORITY = {"principal", "principal_undeclared_span", "trusted_source"}


class _Null:
    def report(self, *a, **k):
        pass


def _sensor(agent_id):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id=agent_id, value_origin="record", reporter=_Null())


def test_a_reused_pool_thread_starts_each_job_without_the_previous_jobs_ledger():
    s = _sensor("reuse")

    def user_a():
        s.scan("Email alice@corp.example the quarterly report.", direction="input")
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    def user_b():          # B never named alice; its tool call precedes any input of B's own
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    with ThreadPoolExecutor(max_workers=1) as pool:      # ONE worker: B runs on A's thread
        a = pool.submit(user_a).result()
        b = pool.submit(user_b).result()
    assert a in AUTHORITY, f"precondition: user A's own call is authorized, got {a!r}"
    assert b == "no_flow", (
        f"user B's call to an address only user A typed read {b!r}: A's principal "
        "authority carried across jobs on a reused pool thread")


def test_a_flow_left_open_in_a_pool_job_ends_with_the_job():
    """begin_flow() without clear_flow(): the explicit ledger it bound belongs to
    the job, and closes when the job ends. B's own input binds B's own ledger, and
    an explicit ledger still survives an input scan WITHIN a request (ruling 3.1:
    one flow spans many inputs)."""
    from xaidr import provenance_chain as pc
    s = _sensor("reuse-open")

    def user_a():
        pc.begin_flow(principal="a")                  # ...and the host never clears it
        s.scan("Email alice@corp.example the quarterly report.", direction="input")
        s.scan("Also copy the team.", direction="input")          # a second turn of A's
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    def user_b():
        s.scan("Send the minutes to the team.", direction="input")       # B's OWN input first
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    with ThreadPoolExecutor(max_workers=1) as pool:
        a = pool.submit(user_a).result()
        b = pool.submit(user_b).result()
    assert a in AUTHORITY, f"user A's flow lost its authority between its own turns: {a!r}"
    assert b not in AUTHORITY, (
        f"user B scanned its own input first and still read {b!r}: user A's open flow kept "
        "its ledger across jobs")
