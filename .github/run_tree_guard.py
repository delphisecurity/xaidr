"""CI guard for tests/test_run_tree.py: read what pytest DID from its JUnit
report and refuse a run in which run-tree capture was not actually exercised.

A test that skips when LangChain is absent passes vacuously, and pytest exits 0
on an all-skipped run. So this names the only cases allowed not to run on each
interpreter, with the reason, and turns every other skip, xfail or failure red.

    python .github/run_tree_guard.py <junit.xml> py312|py310
"""
import sys
import xml.etree.ElementTree as ET

CLASS = "TestRealRunTree"
MINIMUM = 18

INJECTED_MIDDLEWARE = (
    "test_async_create_agent_with_injected_middleware_is_stamped",
    "pre-existing: DelphiMiddleware has no awrap_tool_call, so async create_agent "
    "under protect() raises at its first tool call (strict xfail)")
NOT_RUN = {
    "py312": dict([
        INJECTED_MIDDLEWARE,
        ("test_py310_async_events_are_unplaceable_never_rooted",
         "asserts the Python < 3.11 degradation; skipped from 3.11"),
    ]),
    "py310": dict([
        INJECTED_MIDDLEWARE,
        ("test_t6_canary_async_langchain_still_routes_through_configure",
         "Python < 3.11: no context reaches an async node (strict xfail)"),
        ("test_async_toolnode_graph_is_stamped_on_one_root",
         "Python < 3.11: no context reaches an async node (strict xfail)"),
        ("test_async_create_agent_without_middleware_is_stamped",
         "Python < 3.11: no context reaches an async node (strict xfail)"),
    ]),
}
MUST_PASS = {
    "py312": {"test_t1_every_event_in_one_graph_run_carries_one_root",
              "test_t2_a_reused_child_run_id_in_two_concurrent_flows_never_merges",
              "test_t2_a_collided_root_id_stays_collided_after_the_first_flow_ends",
              "test_t2_two_concurrent_flows_never_share_a_root",
              "test_t2_a_reused_run_id_is_a_collision_never_a_merged_root",
              "test_t5_a_direct_tool_run_is_no_run_and_never_a_synthesized_root",
              "test_t6_canary_sync_langchain_still_routes_through_configure",
              "test_t6_canary_async_langchain_still_routes_through_configure",
              "test_async_toolnode_graph_is_stamped_on_one_root"},
    "py310": {"test_t1_every_event_in_one_graph_run_carries_one_root",
              "test_t2_a_reused_child_run_id_in_two_concurrent_flows_never_merges",
              "test_t2_a_collided_root_id_stays_collided_after_the_first_flow_ends",
              "test_t2_two_concurrent_flows_never_share_a_root",
              "test_t2_a_reused_run_id_is_a_collision_never_a_merged_root",
              "test_t5_a_direct_tool_run_is_no_run_and_never_a_synthesized_root",
              "test_t6_canary_sync_langchain_still_routes_through_configure",
              "test_py310_async_events_are_unplaceable_never_rooted"},
}


def main(path: str, profile: str) -> None:
    cases = [c for c in ET.parse(path).iter("testcase")
             if c.get("classname", "").split(".")[-1] == CLASS]
    allowed = NOT_RUN[profile]
    not_run = {c.get("name"): c.find("skipped").get("message", "")
               for c in cases if c.find("skipped") is not None}
    broken = [c.get("name") for c in cases
              if c.find("failure") is not None or c.find("error") is not None]
    passed = {c.get("name") for c in cases} - set(not_run) - set(broken)
    print(f"{CLASS} ({profile}): collected={len(cases)} passed={len(passed)} "
          f"not run={len(not_run)} failed/errored={len(broken)}")
    for name, why in sorted(not_run.items()):
        verdict = "allowed" if name in allowed else "NOT ALLOWED"
        print(f"  NOT RUN ({verdict}) {name}: pytest said {why!r}")
    problems = []
    if len(cases) < MINIMUM:
        problems.append(f"collected {len(cases)} < {MINIMUM}: the class was removed, "
                        "renamed or deselected, so run-tree capture is unchecked")
    unexpected = sorted(set(not_run) - set(allowed))
    if unexpected:
        problems.append(f"not run without a named reason (LangChain missing?): {unexpected}")
    missing = sorted(MUST_PASS[profile] - passed)
    if missing:
        problems.append(f"required cases did not pass: {missing}")
    if broken:
        problems.append(f"failed/errored: {broken}")
    if problems:
        sys.exit("GUARD RED: " + "; ".join(problems))
    print("GUARD GREEN")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
