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
