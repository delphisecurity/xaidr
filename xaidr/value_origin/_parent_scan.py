"""The parent input scan of an execution context, as a cell a request shares.

``parentScanId`` on a tool-call event names the most recent INPUT scan in the
execution context: the request that authorised the call. A plain ContextVar
would carry it within one task, and lose it the way LangGraph runs nodes: each
node runs in a COPY of the context, so a value an input scan sets inside the
``before_model`` node never reaches the tools node. The value-origin ledger
solves that by binding one OBJECT at the request level, outside every node,
which the copies then share. The parent is held the same way: a one-slot cell,
opened when a request opens (a flow, a request scope, a framework run, an
executor work item: ``value_origin._ledger.request_enter``) and written in place
by every input scan after it. A context with no request yet gets a cell on its
first input scan.

The rule it holds is the paid sensor's, exactly: set when an input event is
emitted (overwriting, so a tool call after turn 5 names turn 5 and never turn 3),
retired at the top of every input scan so an input event has no parent, never
set by an output scan, and None MEANS not evaluated. None never means "search
wider": a tool call with no input scan in its context has no parent, and nothing
looks one up by flow, correlation or run tree.

Stdlib only, inside ``value_origin`` so the vendorable core stays self-contained
(``tests/value_origin_conformance/test_self_contained.py``); ``provenance_chain``
reads it from here.
"""

from __future__ import annotations

import contextvars
from typing import Optional

_CELL: "contextvars.ContextVar[list | None]" = contextvars.ContextVar(
    "xaidr_parent_scan_cell", default=None)


def open_cell() -> None:
    """A new request in this context: no parent until its first input scan.
    The cell is what the request's nodes, tasks and copies then share."""
    _CELL.set([None])


def record(scan_id: Optional[str]) -> None:
    """The input scan just emitted becomes the parent of what follows it here."""
    if not (isinstance(scan_id, str) and scan_id):
        return
    cell = _CELL.get()
    if cell is None:
        cell = [None]
        _CELL.set(cell)
    cell[0] = scan_id


def retire() -> None:
    """At the top of an input scan, and when a request ends: no parent."""
    cell = _CELL.get()
    if cell is not None:
        cell[0] = None


def current() -> Optional[str]:
    """The parent input scan's id, or None for not evaluated."""
    cell = _CELL.get()
    return cell[0] if cell else None
