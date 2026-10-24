"""Value-origin seam state shared by the sensor and the framework patches (A2 M7).

``RESULT_SEAM`` is True while a SCANNED tool-result seam (the LangChain
``BaseTool.run``/``.arun`` patch, the MCP ``ClientSession.call_tool`` patch) is
running the tool. An inner, unscanned seam (``protect_tools``) then leaves the
read for the outer one to record with its result-scan verdict: exactly one
seam records each tool invocation (ARCHITECTURE.md §1.2 item 3, F7). Its own
module so neither side imports the other.
"""
import contextvars
import functools
import inspect
import threading

RESULT_SEAM: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "xaidr_value_origin_result_seam", default=False)


def enclosing_result_seam(fn):
    """``fn`` with ``RESULT_SEAM`` set for the duration of each call, matching
    its sync/async-ness, and always reset (an exception included)."""
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def wrapped(*args, **kwargs):
            token = RESULT_SEAM.set(True)
            try:
                return await fn(*args, **kwargs)
            finally:
                RESULT_SEAM.reset(token)
    else:
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            token = RESULT_SEAM.set(True)
            try:
                return fn(*args, **kwargs)
            finally:
                RESULT_SEAM.reset(token)
    return wrapped


# ── the request (ruling 4, 2026-10-21) ───────────────────────────────────────
# A framework run, an executor work item and a host's request_scope() are each
# one request: the value-origin ledgers bound in it end with it
# (value_origin/_ledger.py, THE REQUEST).

#: True while a framework run hooked by protect() runs INSIDE another hooked run
#: (an Agents SDK ``Agent.as_tool``, a crew kicked off from a tool). Its input is
#: the outer run's MODEL text, so the sensor scans it but does not record it as
#: principal input.
NESTED_RUN: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "xaidr_value_origin_nested_run", default=False)
#: True while an entry hook scans run input that is not the principal's own (an
#: Agents SDK tool output or assistant turn replayed in a run's input list): it is
#: scanned, and not recorded as principal input.
NOT_PRINCIPAL: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "xaidr_value_origin_not_principal", default=False)
_RUN_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar(
    "xaidr_value_origin_run_depth", default=0)
#: While an entry hook scans one input that arrives as several strings, the
#: principal parts each scan would record, collected so the hook records them in
#: ONE write (``DelphiSensor._vo_input_batch``).
INPUT_BATCH: contextvars.ContextVar = contextvars.ContextVar(
    "xaidr_value_origin_input_batch", default=None)


def _enter_run(bind: bool = False):
    from .value_origin import _ledger
    depth = _RUN_DEPTH.get()
    rec = _ledger.request_enter(accumulate=True, kind="run")
    if bind and rec is not None:
        # The run's ledger, bound here, outside every node: a framework that runs
        # its nodes in copies of this context (LangGraph) shares this one object,
        # where a ledger an input scan bound inside a node would die with the node.
        _ledger.bind_run_ledger()
    return (rec, _RUN_DEPTH.set(depth + 1), NESTED_RUN.set(depth > 0))


def _exit_run(state) -> None:
    rec, depth_token, nested_token = state
    for var, token in ((NESTED_RUN, nested_token), (_RUN_DEPTH, depth_token)):
        try:
            var.reset(token)
        except Exception:
            pass                           # exited in another context: nothing to reset there
    try:
        from .value_origin import _ledger
        _ledger.request_exit(rec)
    except Exception:
        pass                               # interpreter shutdown: nothing left to end


def request_scoped_run(fn):
    """``fn`` with each call one request, matching its sync/async-ness; for the
    framework entry hooks (CrewAI kickoff, Agents SDK Runner.run). The request
    opens when the call's body runs, so an async run's request is the awaiting
    task's."""
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def wrapped(*args, **kwargs):
            state = _enter_run()
            try:
                return await fn(*args, **kwargs)
            finally:
                _exit_run(state)
    else:
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            state = _enter_run()
            try:
                return fn(*args, **kwargs)
            finally:
                _exit_run(state)
    return wrapped


def request_scoped_stream(fn, applies):
    """``fn``, a generator or async generator function on a graph object, with
    each run of a graph ``applies`` accepts one request that binds its ledger
    before the first node runs; for LangGraph's ``Pregel.stream`` and
    ``astream``, which ``invoke`` and ``ainvoke`` run through. The request opens
    when the run is first iterated and ends when it finishes or is closed."""
    if inspect.isasyncgenfunction(fn):
        async def scoped_async(agen):
            state = _enter_run(bind=True)
            try:
                async for item in agen:
                    yield item
            finally:
                try:
                    await agen.aclose()
                finally:
                    _exit_run(state)

        @functools.wraps(fn)
        def awrapped(self, *args, **kwargs):
            agen = fn(self, *args, **kwargs)
            return scoped_async(agen) if _applies(applies, self) else agen
        return awrapped

    def scoped(gen):
        state = _enter_run(bind=True)
        try:
            return (yield from gen)
        finally:
            _exit_run(state)

    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        gen = fn(self, *args, **kwargs)
        return scoped(gen) if _applies(applies, self) else gen
    return wrapped


def _applies(applies, obj) -> bool:
    try:
        return bool(applies(obj))
    except Exception:
        return False


_executor_lock = threading.Lock()
_executor_installed = False


def install_executor_requests() -> bool:
    """Make each ``concurrent.futures.ThreadPoolExecutor`` work item one request,
    once per process. A pool thread runs one job after another in one context,
    so without this a ledger bound by one job is still bound for the next one
    on that thread, whoever submitted it. Only xaidr's own context variables are
    touched. Returns whether the seam is in place. Never raises."""
    global _executor_installed
    try:
        with _executor_lock:
            if _executor_installed:
                return True
            from concurrent.futures import thread as _thread
            from .value_origin import _ledger
            original = _thread._WorkItem.run
            if getattr(original, "__xaidr_request__", False):
                _executor_installed = True
                return True

            @functools.wraps(original)
            def run(self, *args, **kwargs):
                rec = _ledger.request_enter()
                try:
                    return original(self, *args, **kwargs)
                finally:
                    _ledger.request_exit(rec)
            run.__xaidr_request__ = True
            _thread._WorkItem.run = run
            _executor_installed = True
            return True
    except Exception:
        return False


_threadpool_installed = False


class _RequestTasks:
    """A ThreadPool worker's task queue whose every task runs as one request."""
    __slots__ = ("_queue",)

    def __init__(self, queue) -> None:
        self._queue = queue

    def get(self, *args, **kwargs):
        task = self._queue.get(*args, **kwargs)
        try:
            job, i, func, fargs, fkwargs = task
        except (TypeError, ValueError):
            return task                       # the sentinel, or a shape not ours to touch
        return (job, i, _one_request(func), fargs, fkwargs)

    def __getattr__(self, name):
        return getattr(self._queue, name)


def _one_request(func):
    from .value_origin import _ledger

    @functools.wraps(func)
    def run(*args, **kwargs):
        rec = _ledger.request_enter()
        try:
            return func(*args, **kwargs)
        finally:
            _ledger.request_exit(rec)
    return run


def install_threadpool_requests() -> bool:
    """Make each ``multiprocessing.pool.ThreadPool`` task one request (an
    ``apply``, or one chunk of a ``map``), once per process, for pools created
    after it. Process pools are untouched. Never raises."""
    global _threadpool_installed
    try:
        with _executor_lock:
            if _threadpool_installed:
                return True
            import multiprocessing.pool as _pool
            import queue as _queue
            original = _pool.worker
            if getattr(original, "__xaidr_request__", False):
                _threadpool_installed = True
                return True

            @functools.wraps(original)
            def worker(inqueue, outqueue, *args, **kwargs):
                if isinstance(inqueue, _queue.SimpleQueue):       # a ThreadPool's own queue
                    inqueue = _RequestTasks(inqueue)
                return original(inqueue, outqueue, *args, **kwargs)
            worker.__xaidr_request__ = True
            _pool.worker = worker
            _threadpool_installed = True
            return True
    except Exception:
        return False
