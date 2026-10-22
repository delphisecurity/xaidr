"""Sabotage harness: remove one piece, run its named test, expect RED with its
message, restore byte-identical (cmp), run again, expect GREEN."""
import hashlib
import os
import shutil
import subprocess
import sys

REPO = "/Users/anirudhkotaru/worktrees/xaidr/run-tree"
PY = sys.argv[1]
T = "tests/test_run_tree.py::"
C = T + "TestRealRunTree::"

CASES = [
    ("S1 stamp call removed from the enqueue funnel", "xaidr/sensor.py",
     "            _run_tree.stamp(data)\n", "            pass\n",
     C + "test_t1_every_event_in_one_graph_run_carries_one_root"),
    ("S2 concurrent roots merged onto the oldest live root", "xaidr/run_tree.py",
     "            if pkey is None:\n                root, path = key, ()\n",
     "            if pkey is None:\n                root, path = (runs[next(iter(runs))].root if runs else key), ()\n",
     C + "test_t2_two_concurrent_flows_never_share_a_root"),
    ("S3 collision detection removed (a reused id is silently ignored)", "xaidr/run_tree.py",
     "                self._collide(key, pkey)\n                return\n",
     "                return\n",
     C + "test_t2_a_reused_run_id_is_a_collision_never_a_merged_root"),
    ("S4 current_root synthesizes a key outside any run", "xaidr/run_tree.py",
     "        enclosing = _enclosing(_current_config())\n        if enclosing is None:\n            return None\n",
     "        enclosing = _enclosing(_current_config())\n        if enclosing is None:\n            import uuid; return str(uuid.uuid4())\n",
     C + "test_current_root_is_the_flow_key_in_process"),
    ("S5 handler try/except removed", "xaidr/run_tree.py",
     "    run_id = kwargs.get(\"run_id\")\n    try:\n        metadata = kwargs.get(\"metadata\")\n"
     "        node = metadata.get(\"langgraph_node\") if isinstance(metadata, dict) else None\n"
     "        name = kwargs.get(\"name\")\n        if name is None and isinstance(serialized, dict):\n"
     "            name = serialized.get(\"name\")\n        INDEX.start(run_id, kwargs.get(\"parent_run_id\"), name, node)\n"
     "    except Exception as exc:\n        INDEX.mark_fault(run_id)\n        _fault(\"handler\", exc)\n",
     "    run_id = kwargs.get(\"run_id\")\n    metadata = kwargs.get(\"metadata\")\n"
     "    node = metadata.get(\"langgraph_node\") if isinstance(metadata, dict) else None\n"
     "    name = kwargs.get(\"name\")\n    if name is None and isinstance(serialized, dict):\n"
     "        name = serialized.get(\"name\")\n    INDEX.start(run_id, kwargs.get(\"parent_run_id\"), name, node)\n",
     C + "test_t3_a_faulting_handler_never_reaches_the_host_or_the_log"),
    ("S6 stamp except clause removed (re-raises)", "xaidr/run_tree.py",
     "    except Exception as exc:\n        for key in (\"runRootId\",",
     "    except ZeroDivisionError as exc:\n        for key in (\"runRootId\",",
     C + "test_t3_a_faulting_stamp_never_costs_the_event_or_the_verdict"),
    ("S7 eviction removed", "xaidr/run_tree.py",
     "            while len(runs) > self._cap:\n                self._evict_root(runs[next(iter(runs))].root)\n",
     "            pass\n",
     T + "test_t4_abandoned_roots_are_evicted_under_the_cap"),
    ("S7b eviction removed (memory budget)", "xaidr/run_tree.py",
     "            while len(runs) > self._cap:\n                self._evict_root(runs[next(iter(runs))].root)\n",
     "            pass\n",
     T + "test_d4_budget_index_stays_under_2mb_with_many_flows"),
    ("S8 a root synthesized for a no-run event", "xaidr/run_tree.py",
     "            data[\"runTree\"] = UNKNOWN_RUN if _unplaceable() else NO_RUN\n            return\n",
     "            import uuid as _u\n            data[\"runTree\"] = UNKNOWN_RUN if _unplaceable() else NO_RUN\n"
     "            data[\"runRootId\"] = str(_u.uuid4())\n            return\n",
     C + "test_t5_a_direct_tool_run_is_no_run_and_never_a_synthesized_root"),
    ("S9 unprotect no longer stops stamping", "xaidr/autopatch/frameworks.py",
     "        run_tree.activate()\n        return run_tree.deactivate\n",
     "        run_tree.activate()\n        return lambda: None\n",
     C + "test_t5_protect_twice_is_idempotent_and_unprotect_detaches"),
    ("S10 configure wrapper attaches nothing (LangChain routing around configure)",
     "xaidr/run_tree.py",
     "    handler = _handler\n    if handler is None or not _active:\n        return\n",
     "    handler = _handler\n    if True:\n        return\n",
     C + "test_t6_canary_sync_langchain_still_routes_through_configure"),
    ("S11 tool_call_id not bound around the tool-result scan", "xaidr/autopatch/frameworks.py",
     "            token = run_tree.bind_tool_call_id(kwargs.get(\"tool_call_id\"))\n            try:\n"
     "                verdict = ctx.sensor.scan(text, direction=\"tool_result\")\n",
     "            token = None\n            try:\n"
     "                verdict = ctx.sensor.scan(text, direction=\"tool_result\")\n",
     C + "test_t7_a_tool_result_joins_its_tool_call_by_tool_call_id"),
    ("S12 AsyncCallbackManager.configure not wrapped", "xaidr/autopatch/frameworks.py",
     "    ctx.try_install(\n        \"langchain_core.callbacks.manager\", \"AsyncCallbackManager.configure\",\n",
     "    (lambda *a, **k: None)(\n        \"langchain_core.callbacks.manager\", \"AsyncCallbackManager.configure\",\n",
     C + "test_async_toolnode_graph_is_stamped_on_one_root"),
    ("S12b AsyncCallbackManager.configure not wrapped (canary)", "xaidr/autopatch/frameworks.py",
     "    ctx.try_install(\n        \"langchain_core.callbacks.manager\", \"AsyncCallbackManager.configure\",\n",
     "    (lambda *a, **k: None)(\n        \"langchain_core.callbacks.manager\", \"AsyncCallbackManager.configure\",\n",
     C + "test_t6_canary_async_langchain_still_routes_through_configure"),
    ("S13 schema run-tree passthrough removed", "xaidr/schema.py",
     "    _passthrough_run_tree(data, out)\n", "",
     T + "test_schema_maps_the_run_keys_and_omits_them_when_absent"),
    ("S14 stamp made slow", "xaidr/run_tree.py",
     "    if not _active:\n        return\n    try:\n        call_id = _TOOL_CALL_ID.get()\n",
     "    if not _active:\n        return\n    import time as _t\n    _e = _t.perf_counter_ns() + 15000\n"
     "    while _t.perf_counter_ns() < _e:\n        pass\n    try:\n        call_id = _TOOL_CALL_ID.get()\n",
     T + "test_d4_budget_stamp_p99_at_most_10us"),
    ("S15 callback made slow", "xaidr/run_tree.py",
     "def _on_end(kwargs: dict) -> None:\n    if not _active:\n        return\n    try:\n",
     "def _on_end(kwargs: dict) -> None:\n    if not _active:\n        return\n    import time as _t\n"
     "    _e = _t.perf_counter_ns() + 15000\n    while _t.perf_counter_ns() < _e:\n        pass\n    try:\n",
     T + "test_d4_budget_callback_p99_at_most_10us"),
    ("S16 run-tree target removed from TARGETS", "xaidr/autopatch/frameworks.py",
     "    FrameworkTarget(\n        \"langchain-run-tree\", (\"langchain_core.callbacks.manager\",),\n"
     "        _patch_langchain_run_tree,\n"
     "        \"run tree: flow key, task, parent and graph node on every event\",\n    ),\n",
     "",
     T + "test_t5_without_langchain_no_run_keys_and_the_manifest_says_so"),
    ("S18 a reused id marks only the newcomer's root collided", "xaidr/run_tree.py",
     "        for holder in (self._runs.get(key),\n                       self._runs.get(pkey) if pkey is not None else None):\n",
     "        for holder in (self._runs.get(pkey) if pkey is not None else None,):\n",
     T + "test_t2_index_a_reused_child_id_collides_both_flows"),
    ("S18b same, a root id equal to a live child", "xaidr/run_tree.py",
     "        for holder in (self._runs.get(key),\n                       self._runs.get(pkey) if pkey is not None else None):\n",
     "        for holder in (self._runs.get(pkey) if pkey is not None else None,):\n",
     T + "test_t2_index_a_root_id_equal_to_a_live_child_collides"),
    ("S19 ended ids forgotten (no memo of ended runs)", "xaidr/run_tree.py",
     "            if key in runs or key in self._tainted or key in self._ended:\n",
     "            if key in runs or key in self._tainted:\n",
     T + "test_t2_index_a_root_id_reused_after_its_flow_ended_is_a_collision"),
    ("S20 resolve ignores tainted ids (a reused id reads unknown_run, not collision)", "xaidr/run_tree.py",
     "        if run is None:\n            if key in self._tainted:\n                return COLLISION, None\n",
     "        if run is None:\n            if False:\n                return COLLISION, None\n",
     T + "test_t2_index_a_collided_root_id_stays_collided_after_the_first_flow_ends"),
    ("S21 in-flight handler indexes after unprotect", "xaidr/run_tree.py",
     "def _on_start(kwargs: dict, serialized: Any) -> None:\n    if not _active:\n        return\n",
     "def _on_start(kwargs: dict, serialized: Any) -> None:\n",
     C + "test_t5_unprotect_stops_indexing_runs_already_in_flight"),
    ("S22 every run carries an eager member set", "xaidr/run_tree.py",
     "        self.members: Optional[set] = None\n",
     "        self.members: Optional[set] = set()\n",
     T + "test_d4_budget_index_stays_under_2mb_with_many_flows"),
    ("S23 handler made a no-op (benchmark vacuity guard)", "xaidr/run_tree.py",
     "    run_id = kwargs.get(\"run_id\")\n    try:\n        metadata = kwargs.get(\"metadata\")\n",
     "    return\n    run_id = kwargs.get(\"run_id\")\n    try:\n        metadata = kwargs.get(\"metadata\")\n",
     T + "test_d4_budget_callback_p99_at_most_10us"),
    ("S17 the Python < 3.11 unplaceable label removed", "xaidr/run_tree.py",
     "    return sys.version_info < (3, 11) and len(INDEX) > 0\n",
     "    return False\n",
     C + "test_py310_async_events_are_unplaceable_never_rooted"),
]

ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": REPO}


def run(test):
    p = subprocess.run([PY, "-m", "pytest", test, "-q", "-p", "no:cacheprovider", "-x"],
                       cwd=REPO, env=ENV, capture_output=True, text=True, timeout=300)
    out = p.stdout + p.stderr
    tail = [l for l in out.splitlines() if l.strip()][-1]
    msg = next((l.strip() for l in out.splitlines()
                if l.startswith("E ") and ("Error" in l or "assert" in l.lower())), "")
    return p.returncode, tail, msg[:420]


only = set(sys.argv[2:])
for name, rel, old, new, test in CASES:
    if only and name.split()[0] not in only:
        continue
    path = os.path.join(REPO, rel)
    backup = path + ".sabotage-orig"
    src = open(path, encoding="utf-8").read()
    assert src.count(old) == 1, f"{name}: anchor found {src.count(old)} times"
    shutil.copy2(path, backup)
    before = hashlib.sha256(open(path, "rb").read()).hexdigest()
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    try:
        rc, tail, msg = run(test)
    finally:
        shutil.copy2(backup, path)
        os.remove(backup)
    same = hashlib.sha256(open(path, "rb").read()).hexdigest() == before
    rc2, tail2, _ = run(test)
    print(f"=== {name}\n  test: {test.split('::')[-1]}\n  RED   (rc={rc}): {tail}\n    {msg}\n"
          f"  restored ({'sha256 identical' if same else 'RESTORE MISMATCH'})\n  GREEN (rc={rc2}): {tail2}")
    if rc == 0 or rc2 != 0:
        print("  !!! SABOTAGE PROOF FAILED for this case")
