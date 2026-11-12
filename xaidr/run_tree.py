"""Run-tree capture: which LangChain/LangGraph run each telemetry event came from.

Every event emitted while a LangChain run is executing is stamped with the ROOT
run id LangChain minted for that invocation (``runRootId``, the flow key), the
run executing at emit time (``runTaskId``), its parent (``runParentId``), the
graph node and its path from the root, the LangGraph step, and a per-root
sequence number (``runSeq``), because the Brain stores events in ingest order
and cannot recover the order a flow produced them in. The design and the
rulings it follows are in ``docs/run-tree-spec.md``.

HOW IT ATTACHES. ``protect()`` wraps the public ``CallbackManager.configure``
and ``AsyncCallbackManager.configure`` classmethods so every callback manager
LangChain configures carries one :class:`RunTreeHandler`. Nothing here imports
a framework module: the handler's base class and the config ContextVar are read
out of ``sys.modules``, which is rule 1 of ``protect()``.

HOW IT STAMPS. The handler only indexes runs: run id -> (root, parent, node
path). The stamp reads LangChain's own ``var_child_runnable_config``, which
LangChain sets for every runnable and LangGraph carries into the thread running
each node, so it sees the caller's run on whatever thread emits the event. The
sensor calls :func:`stamp` once per event from its single enqueue funnel.

THE SAFETY RULE, which every status below follows. A flow split under two roots
costs a join. Two flows merged under one root let one flow's input vouch for
the other's tool call. So every ambiguous case resolves to NO key, never to the
nearest plausible root:

    stamped      the emitting run is indexed; the ids are present
    no_run       no LangChain run config reached the point the event was
                 emitted: it ran outside every run, or on a thread the host
                 started without copying its context; no ids, and no root is
                 ever synthesized for it
    unknown_run  the event cannot be placed: inside a run the index never saw
                 start (begun before protect(), or evicted), or, on Python
                 < 3.11, with no run config while runs are live, where LangChain
                 cannot carry the config into async nodes (see
                 :func:`_unplaceable`); no ids
    collision    the run id has named more than one run (a caller-supplied
                 run_id reused, at once or one flow after another); no ids for
                 any flow that touched it, from then on
    fault        the handler or the stamp raised for this run; no ids

THE CONTRACT. Never raises into the host or into LangChain. Never logs an
exception message, only its type, once. Never reads or changes a verdict: the
stamp runs after the event is built and only adds keys. Bounded: a stamp is a
constant number of dict reads; a callback is a constant number of dict
operations, except a root's end or eviction, which is linear in the runs still
filed under that root; a live-run cap with oldest-root eviction; and bounded
memos. The index holds run ids, node names and counters, never content.
"""

from __future__ import annotations

import logging
import sys
import threading
from contextvars import ContextVar, Token
from typing import Any, Optional
from uuid import UUID

logger = logging.getLogger("xaidr.run_tree")

RUN_SOURCE = "langchain"
#: Live runs the index holds before evicting the oldest root and its runs.
MAX_LIVE_RUNS = 4096
#: Node names kept in ``runNodePath``, root side truncated past it.
MAX_NODE_PATH = 8
#: Longest node name or tool-call id carried on an event.
MAX_NAME_CHARS = 128
#: First element of a ``runNodePath`` that lost names on the root side.
TRUNCATED = "…"
#: Run ids each memo (faulted, collided, ended) remembers, oldest dropped first.
_MAX_MEMO = 4096

STAMPED, NO_RUN, UNKNOWN_RUN, COLLISION, FAULT = (
    "stamped", "no_run", "unknown_run", "collision", "fault")


class _Run:
    """One live run. Ids are ``uuid.int``: the int a ``UUID`` already holds, so
    the index keeps no wrapper alive of its own. ``members``, ``seq`` and
    ``collided`` are used on a root's entry only."""

    __slots__ = ("root", "parent", "path", "members", "seq", "collided", "keys")

    def __init__(self, root: int, parent: Optional[int], path: tuple) -> None:
        self.root = root
        self.parent = parent
        self.path = path
        self.members: Optional[set] = None
        self.seq = 0
        self.collided = False
        # (root id, own id, parent id) as event strings, built once by the first
        # stamp and reused: a UUID's text never changes, and building it is most
        # of a stamp's cost.
        self.keys: Optional[tuple] = None


def _bounded(name: Any) -> Optional[str]:
    if not isinstance(name, str) or not name:
        return None
    return name[:MAX_NAME_CHARS]


def _remember(memo: dict, key: int, cap: int) -> None:
    memo.pop(key, None)
    memo[key] = None
    while len(memo) > cap:
        del memo[next(iter(memo))]


class RunTreeIndex:
    """Live LangChain runs: run id -> (root, parent, node path).

    A root is computed when a run STARTS, from its parent's entry, so a lookup
    never walks the tree. Each run's entry is dropped when that run ends, and a
    root's end drops everything still filed under it, so the index tracks live
    runs. A run whose end never fires (an abandoned generator, a killed thread)
    is reclaimed by the cap, oldest root first. A callback is a constant number
    of dict operations, except a root's end or eviction, which is linear in the
    runs still filed under that root and so bounded by the cap.

    A RUN ID IS A FLOW KEY ONLY THE FIRST TIME IT IS SEEN. LangChain mints a
    fresh id per run; a caller can pass its own ``run_id``, and then one id can
    name two flows. Any start that reuses an id that is live, recently ended or
    already collided taints that id and marks every root it touches collided,
    and a tainted id resolves to ``collision`` from then on. So two flows never
    resolve to one root: the reuse costs both of them their key instead.
    """

    def __init__(self, cap: int = MAX_LIVE_RUNS) -> None:
        self._cap = cap
        self._lock = threading.Lock()
        # run id -> _Run, in start order; the oldest entry names the root to
        # evict first.
        self._runs: dict = {}
        # Bounded memos: ids whose runs faulted, ids that collided, and ids
        # whose runs ended or were evicted.
        self._faulted: dict = {}
        self._tainted: dict = {}
        self._ended: dict = {}

    def __len__(self) -> int:
        return len(self._runs)

    def clear(self) -> None:
        with self._lock:
            self._runs.clear()
            self._faulted.clear()
            self._tainted.clear()
            self._ended.clear()

    # ── writes (callbacks) ───────────────────────────────────────────────

    def start(self, run_id: Any, parent_run_id: Any, name: Any = None,
              node: Any = None) -> None:
        if not isinstance(run_id, UUID):
            return
        if parent_run_id is not None and not isinstance(parent_run_id, UUID):
            return
        node = _bounded(node)
        key = run_id.int
        pkey = parent_run_id.int if parent_run_id is not None else None
        with self._lock:
            runs = self._runs
            if key in runs or key in self._tainted or key in self._ended:
                self._collide(key, pkey)
                return
            if pkey is None:
                root, path = key, ()
            else:
                parent = runs.get(pkey)
                if parent is None:
                    if pkey in self._tainted:
                        _remember(self._tainted, key, _MAX_MEMO)
                    elif pkey in self._faulted:
                        _remember(self._faulted, key, _MAX_MEMO)
                    return
                root, path = parent.root, parent.path
                root_run = runs.get(root)
                if root_run is None:
                    return
                if root_run.members is None:
                    root_run.members = set()
                root_run.members.add(key)
            if node is not None and (name == node or not path or path[-1] != node):
                path = path + (node,)
                if len(path) > MAX_NODE_PATH:
                    path = (TRUNCATED,) + path[-(MAX_NODE_PATH - 1):]
            runs[key] = _Run(root, pkey, path)
            while len(runs) > self._cap:
                self._evict_root(runs[next(iter(runs))].root)

    def _collide(self, key: int, pkey: Optional[int]) -> None:
        _remember(self._tainted, key, _MAX_MEMO)
        for holder in (self._runs.get(key),
                       self._runs.get(pkey) if pkey is not None else None):
            if holder is None:
                continue
            root_run = self._runs.get(holder.root)
            if root_run is not None:
                root_run.collided = True
            _remember(self._tainted, holder.root, _MAX_MEMO)

    def end(self, run_id: Any) -> None:
        if not isinstance(run_id, UUID):
            return
        key = run_id.int
        with self._lock:
            run = self._runs.pop(key, None)
            if run is None:
                return
            _remember(self._ended, key, _MAX_MEMO)
            if run.root == key:
                for member in run.members or ():
                    self._runs.pop(member, None)
            else:
                root_run = self._runs.get(run.root)
                if root_run is not None and root_run.members is not None:
                    root_run.members.discard(key)

    def mark_fault(self, run_id: Any) -> None:
        if isinstance(run_id, UUID):
            with self._lock:
                _remember(self._faulted, run_id.int, _MAX_MEMO)

    def _evict_root(self, root: int) -> None:
        root_run = self._runs.pop(root, None)
        _remember(self._ended, root, _MAX_MEMO)
        for member in (root_run.members if root_run is not None else None) or ():
            if self._runs.pop(member, None) is not None:
                _remember(self._ended, member, _MAX_MEMO)

    # ── reads (stamp) ────────────────────────────────────────────────────

    def resolve(self, run_id: Any) -> tuple:
        """``(status, run)``: ``run`` is set only when the status is stamped."""
        if not isinstance(run_id, UUID):
            return UNKNOWN_RUN, None
        key = run_id.int
        run = self._runs.get(key)
        if run is None:
            if key in self._tainted:
                return COLLISION, None
            if key in self._faulted:
                return FAULT, None
            return UNKNOWN_RUN, None
        root_run = self._runs.get(run.root)
        if root_run is None:
            return UNKNOWN_RUN, None
        if root_run.collided or key in self._tainted:
            return COLLISION, None
        return STAMPED, run

    def next_seq(self, root: int) -> int:
        with self._lock:
            root_run = self._runs.get(root)
            if root_run is None:
                return 0
            root_run.seq += 1
            return root_run.seq


#: The process's one index. Run trees are a fact about the process, not about a
#: sensor, so every sensor's events resolve against the same runs.
INDEX = RunTreeIndex()

_active = False
_fault_logged = False
_handler: Any = None
_handler_lock = threading.Lock()

#: LangChain's tool_call_id for the tool call being scanned right now, bound by
#: the tool seams around their scan so the event can carry ``toolCallId``. It is
#: unique only within a flow, so it joins a result to its call together with
#: ``runRootId``.
_TOOL_CALL_ID: ContextVar[Optional[str]] = ContextVar("xaidr_tool_call_id", default=None)


def _fault(where: str, exc: BaseException) -> None:
    global _fault_logged
    if not _fault_logged:
        _fault_logged = True
        try:
            logger.warning(
                "xaidr run-tree: %s faulted (%s); affected events carry "
                "runTree='fault' [message suppressed: may contain content]",
                where, type(exc).__name__)
        except Exception:
            pass


# ── activation (owned by protect()) ──────────────────────────────────────


def activate() -> None:
    global _active
    _active = True


def deactivate() -> None:
    global _active
    _active = False
    INDEX.clear()


def is_active() -> bool:
    return _active


# ── the handler ──────────────────────────────────────────────────────────


def _on_start(kwargs: dict, serialized: Any) -> None:
    if not _active:
        return
    run_id = kwargs.get("run_id")
    try:
        metadata = kwargs.get("metadata")
        node = metadata.get("langgraph_node") if isinstance(metadata, dict) else None
        name = kwargs.get("name")
        if name is None and isinstance(serialized, dict):
            name = serialized.get("name")
        INDEX.start(run_id, kwargs.get("parent_run_id"), name, node)
    except Exception as exc:
        INDEX.mark_fault(run_id)
        _fault("handler", exc)


def _on_end(kwargs: dict) -> None:
    if not _active:
        return
    try:
        INDEX.end(kwargs.get("run_id"))
    except Exception as exc:
        _fault("handler", exc)


def _handler_class(base: type) -> type:
    class RunTreeHandler(base):  # type: ignore[misc, valid-type]
        """Indexes LangChain runs for the stamp. Added to every configured
        callback manager by the ``configure`` wrapper ``protect()`` installs."""

        run_inline = True
        raise_error = False

        def on_chain_start(self, serialized: Any = None, *args: Any, **kwargs: Any) -> None:
            _on_start(kwargs, serialized)

        def on_chat_model_start(self, serialized: Any = None, *args: Any, **kwargs: Any) -> None:
            _on_start(kwargs, serialized)

        def on_llm_start(self, serialized: Any = None, *args: Any, **kwargs: Any) -> None:
            _on_start(kwargs, serialized)

        def on_tool_start(self, serialized: Any = None, *args: Any, **kwargs: Any) -> None:
            _on_start(kwargs, serialized)

        def on_retriever_start(self, serialized: Any = None, *args: Any, **kwargs: Any) -> None:
            _on_start(kwargs, serialized)

        def on_chain_end(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_chain_error(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_llm_end(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_llm_error(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_tool_end(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_tool_error(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_retriever_end(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

        def on_retriever_error(self, *args: Any, **kwargs: Any) -> None:
            _on_end(kwargs)

    return RunTreeHandler


def handler_for(base: type) -> Any:
    """The process's one handler, subclassing LangChain's ``base`` handler."""
    global _handler
    with _handler_lock:
        if _handler is None or not isinstance(_handler, base):
            _handler = _handler_class(base)()
        return _handler


def attach(manager: Any) -> None:
    """Add the handler to a freshly configured callback manager, once."""
    handler = _handler
    if handler is None or not _active:
        return
    handlers = getattr(manager, "handlers", None)
    if handlers is None or any(h is handler for h in handlers):
        return
    manager.add_handler(handler, True)


# ── the stamp ────────────────────────────────────────────────────────────


def bind_tool_call_id(value: Any) -> Optional[Token]:
    """Bind LangChain's tool_call_id around a tool seam's scan. Never raises."""
    try:
        if isinstance(value, str) and value:
            return _TOOL_CALL_ID.set(value[:MAX_NAME_CHARS])
    except Exception:
        pass
    return None


def reset_tool_call_id(token: Optional[Token]) -> None:
    if token is not None:
        try:
            _TOOL_CALL_ID.reset(token)
        except Exception:
            pass


def _current_config() -> Optional[dict]:
    module = sys.modules.get("langchain_core.runnables.config")
    var = getattr(module, "var_child_runnable_config", None) if module else None
    if var is None:
        return None
    cfg = var.get()
    return cfg if isinstance(cfg, dict) else None


def _enclosing(cfg: Optional[dict]) -> Optional[UUID]:
    if cfg is None:
        return None
    enclosing = getattr(cfg.get("callbacks"), "parent_run_id", None)
    return enclosing if isinstance(enclosing, UUID) else None


def _unplaceable() -> bool:
    """True when a missing run config does NOT establish "outside any run".

    LangChain sets the run config in a copied context and hands it to async
    code through ``asyncio.create_task(context=...)``, which Python added in
    3.11 (``langchain_core.runnables.utils.asyncio_accepts_context``). Before
    3.11 an async node runs without it, and so does any sync tool it dispatches
    to an executor thread, which copies the context it was called from. There an
    event with no config may belong to a live run, so while any run is live it
    reports ``unknown_run`` (cannot place) rather than ``no_run``; neither
    carries ids. From 3.11 the config reaches every node, and a missing one
    means the event is outside every run.
    """
    return sys.version_info < (3, 11) and len(INDEX) > 0


def stamp(data: dict) -> None:
    """Add the run keys to one event's ``data``. Never raises; adds keys only."""
    if not _active:
        return
    try:
        call_id = _TOOL_CALL_ID.get()
        if call_id is not None:
            data["toolCallId"] = call_id
        cfg = _current_config()
        enclosing = _enclosing(cfg)
        if enclosing is None:
            data["runTree"] = UNKNOWN_RUN if _unplaceable() else NO_RUN
            return
        status, run = INDEX.resolve(enclosing)
        data["runTree"] = status
        if run is None:
            return
        keys = run.keys
        if keys is None:
            keys = run.keys = (str(UUID(int=run.root)), str(enclosing),
                               None if run.parent is None else str(UUID(int=run.parent)))
        data["runRootId"] = keys[0]
        data["runTaskId"] = keys[1]
        if keys[2] is not None:
            data["runParentId"] = keys[2]
        metadata = cfg.get("metadata") if cfg else None
        if isinstance(metadata, dict):
            node = _bounded(metadata.get("langgraph_node"))
            if node is not None:
                data["runNode"] = node
            step = metadata.get("langgraph_step")
            if isinstance(step, int) and not isinstance(step, bool) and step >= 0:
                data["runStep"] = step
        if run.path:
            data["runNodePath"] = list(run.path)
        data["runSeq"] = INDEX.next_seq(run.root)
        data["runSource"] = RUN_SOURCE
    except Exception as exc:
        for key in ("runRootId", "runTaskId", "runParentId", "runNode",
                    "runNodePath", "runStep", "runSeq", "runSource"):
            data.pop(key, None)
        try:
            data["runTree"] = FAULT
        except Exception:
            pass
        _fault("stamp", exc)


def current_root() -> Optional[str]:
    """The flow key for the run executing now, or None.

    For in-process consumers that need one state per flow (value origin's
    ledger): None whenever the status is anything but stamped, so a collision,
    an unknown run or a fault never hands two flows the same key.
    """
    if not _active:
        return None
    try:
        enclosing = _enclosing(_current_config())
        if enclosing is None:
            return None
        status, run = INDEX.resolve(enclosing)
        return str(UUID(int=run.root)) if status == STAMPED and run is not None else None
    except Exception as exc:
        _fault("current_root", exc)
        return None
