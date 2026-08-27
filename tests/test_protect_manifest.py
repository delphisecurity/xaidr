"""``xaidr.protect()`` — the four non-negotiable constraints, and the manifest.

The constraints are what make this auditable rather than magic, so each one has
its own section and each is demonstrated rather than asserted in prose:

  C1  patch ONLY what is already in sys.modules — never import to patch
  C2  explicit call — nothing happens at import time
  C3  a manifest, LOUDLY — present-but-unpatched is impossible to miss
  C4  idempotent — a second protect() does not double-wrap

Framework fixtures come from ``tests/fake_frameworks.py``; read its docstring
for exactly how far these tests do and do not generalise to the real libraries.
"""

from __future__ import annotations

import subprocess
import sys
import warnings

import pytest

import xaidr
from xaidr.autopatch import active_manifests
from xaidr.autopatch.core import is_xaidr_wrapper
from xaidr.autopatch.frameworks import TARGETS_BY_NAME
from xaidr.autopatch.manifest import ProtectionManifest, XaidrProtectionWarning

import fake_frameworks as fakes

FAKE_PREFIXES = (
    "langchain", "langchain_core", "langgraph", "agents", "crewai",
    "autogen", "autogen_core", "llama_index", "mcp", "requests",
)


@pytest.fixture(autouse=True)
def _clean_patch_state():
    """Every test starts with nothing patched and no fake framework loaded."""
    fakes.uninstall(FAKE_PREFIXES)
    yield
    xaidr.unprotect()
    fakes.uninstall(FAKE_PREFIXES)


def _absent() -> set[str]:
    """Framework names genuinely not importable in this interpreter.

    httpx IS installed (it is the [http] extra), and other test modules import
    it, so "not present" is a property of the environment rather than a
    constant. Computing it keeps these tests order-independent.
    """
    return {
        name for name, target in TARGETS_BY_NAME.items() if not target.present()
    }


def _protect(**kwargs) -> ProtectionManifest:
    kwargs.setdefault("agent_id", "protect-test")
    kwargs.setdefault("quiet", True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", XaidrProtectionWarning)
        return xaidr.protect(**kwargs)


def crewai_hook_registered() -> bool:
    """True when protect() has an xaidr before_tool_call hook on CrewAI.

    The CrewAI tool boundary is a REGISTERED HOOK, not a patched attribute, so
    ``is_xaidr_wrapper(crewai.tools.BaseTool.run)`` is the wrong question — and
    was the wrong question before the seam changed, because the agent path
    never went through ``BaseTool.run`` in the first place. Asking the registry
    is the only reading of "is the tool boundary instrumented" that can be
    wrong in a way that matters.
    """
    hooks = sys.modules.get("crewai.hooks")
    if hooks is None:
        return False
    return any(
        getattr(h, "__name__", "") == "before_tool_call"
        and getattr(h, "__module__", "").endswith("integrations.crewai")
        for h in hooks.get_before_tool_call_hooks()
    )


# ═══════════════════════════════════════════════════════════════════════
# C1 — patch only what is already in sys.modules
# ═══════════════════════════════════════════════════════════════════════


def test_protect_imports_no_framework_it_does_not_find():
    """The zero-dependency promise: protect() must not pull in a framework.

    This is the constraint Cisco's SDK does not keep, and it is the whole reason
    `pip install xaidr` stays dependency-free — so it is checked as an identity
    on sys.modules, not trusted to code review.
    """
    before = set(sys.modules)
    manifest = _protect()
    appeared = {m for m in set(sys.modules) - before if not m.startswith("xaidr")}
    assert appeared == set(), f"protect() imported: {sorted(appeared)}"
    for name in FAKE_PREFIXES:
        assert name not in sys.modules, name
    # And it told the truth about what it did not find.
    assert set(manifest.not_present) == _absent()


def test_only_the_imported_framework_is_touched():
    fakes.install_langchain_core()
    manifest = _protect()

    fake_targets = [
        r.target for r in manifest.patched if r.framework in set(FAKE_PREFIXES) | {"langchain_core"}
    ]
    assert fake_targets == [
        "langchain_core.tools.BaseTool.run",
        "langchain_core.tools.BaseTool.arun",
    ]
    assert "crewai" in manifest.not_present
    assert "crewai" not in sys.modules


def test_a_present_package_with_an_unimported_submodule_is_not_reached():
    """`langchain_core` imported but `langchain_core.tools` not.

    getattr(langchain_core, "tools") would trigger a lazy submodule import on a
    real package, so the resolver requires the EXACT sys.modules key. The
    framework is present, so this is a loud unpatchable — not a quiet skip.
    """
    fakes.install_langchain_core()
    del sys.modules["langchain_core.tools"]

    manifest = _protect(targets=["langchain_core"])
    assert not manifest.patched
    assert [r.framework for r in manifest.found_unpatchable] == ["langchain_core"]
    assert "not in sys.modules" in manifest.found_unpatchable[0].detail
    assert "langchain_core.tools" not in sys.modules


def test_the_rule_1_self_check_fires_when_a_patcher_imports(monkeypatch):
    """The detector that keeps rule 1 honest is itself non-vacuous."""
    import xaidr.autopatch.frameworks as fw

    def rogue(ctx):
        import textwrap  # noqa: F401 — a module protect() had no business loading
        sys.modules["definitely_not_imported_before"] = sys.modules["textwrap"]

    target = fw.FrameworkTarget("httpx", ("httpx",), rogue, "rogue")
    monkeypatch.setattr(fw, "TARGETS", (target,))
    monkeypatch.setattr("xaidr.autopatch.TARGETS", (target,))
    import httpx  # noqa: F401

    try:
        manifest = _protect()
        assert any("RULE 1 VIOLATION" in n for n in manifest.notes), manifest.notes
    finally:
        sys.modules.pop("definitely_not_imported_before", None)


# ═══════════════════════════════════════════════════════════════════════
# C2 — explicit call, never import-time magic
# ═══════════════════════════════════════════════════════════════════════


def test_importing_xaidr_patches_nothing():
    """A security control that installs itself cannot be audited.

    Run in a subprocess so this cannot be confused by patches an earlier test
    in this process installed.
    """
    code = (
        "import httpx, sys;"
        "before = httpx.Client.send;"
        "import xaidr;"
        "assert httpx.Client.send is before, 'xaidr patched httpx at import time';"
        "assert not xaidr.autopatch.active_manifests();"
        "assert callable(xaidr.protect);"
        "print('clean')"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert out.returncode == 0, out.stderr
    assert "clean" in out.stdout


def test_protect_is_the_only_thing_that_patches():
    import httpx

    before = httpx.Client.send
    assert not is_xaidr_wrapper(before)
    manifest = _protect(targets=["httpx"])
    assert is_xaidr_wrapper(httpx.Client.send)
    manifest.unprotect()
    assert httpx.Client.send is before


# ═══════════════════════════════════════════════════════════════════════
# C3 — return a manifest, LOUDLY
# ═══════════════════════════════════════════════════════════════════════


def test_manifest_carries_the_three_required_keys():
    manifest = _protect()
    assert sorted(dict(manifest)) == ["found_unpatchable", "not_present", "patched"]
    assert manifest["patched"] is manifest.patched
    payload = manifest.to_dict()
    import json

    json.dumps(payload)  # must be loggable as-is
    assert set(payload) >= {"patched", "found_unpatchable", "not_present"}


def test_a_present_but_unpatchable_framework_warns_and_shouts(capsys):
    """THE failure mode this project spent a month eliminating.

    langchain is importable but has no create_agent — a pre-1.0 install. That
    boundary is UNPROTECTED, and the developer must not be able to miss it.
    """
    fakes.install_langchain(with_create_agent=False)

    with pytest.warns(XaidrProtectionWarning, match="was NOT instrumented"):
        manifest = xaidr.protect(agent_id="a", quiet=True)

    assert not manifest.fully_covered
    entry = next(r for r in manifest.found_unpatchable if r.framework == "langchain")
    assert "langchain<1.0" in entry.detail

    err = capsys.readouterr().err
    assert "[xaidr]" in err and "NOT instrumented" in err

    rendered = repr(manifest)
    assert "UNPROTECTED" in rendered
    # The unprotected section must come BEFORE the patched one: a reader who
    # stops after the first section must still have seen the gap.
    assert rendered.index("PRESENT BUT NOT PATCHED") < rendered.index("PATCHED (")


def test_quiet_silences_the_banner_but_never_an_unprotected_boundary(capsys):
    fakes.install_langchain(with_create_agent=False)
    with pytest.warns(XaidrProtectionWarning):
        xaidr.protect(agent_id="a", quiet=True)
    quiet_err = capsys.readouterr().err
    assert "NOT instrumented" in quiet_err
    assert "xaidr.protect() manifest" not in quiet_err

    xaidr.unprotect()
    with pytest.warns(XaidrProtectionWarning):
        xaidr.protect(agent_id="a", quiet=False)
    loud_err = capsys.readouterr().err
    assert "NOT instrumented" in loud_err
    assert "xaidr.protect() manifest" in loud_err


def test_nothing_installed_still_returns_a_usable_manifest():
    """HARD GATE 5: importing xaidr with no frameworks present still works.

    In a SUBPROCESS, because this process has already imported httpx and the
    gate is about a genuinely bare interpreter — one where `pip install xaidr`
    pulled in nothing at all.
    """
    code = (
        "import xaidr, sys;"
        "m = xaidr.protect(agent_id='bare');"
        "assert m.patched == [], m.patched;"
        "assert m.found_unpatchable == [], m.found_unpatchable;"
        "assert len(m.not_present) == 11, m.not_present;"
        "assert m.fully_covered;"
        "assert 'nothing was instrumented' in repr(m);"
        "print('bare-ok')"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert out.returncode == 0, out.stderr
    assert "bare-ok" in out.stdout
    # "you never imported it" is not an unprotected boundary, so nothing shouts.
    assert "NOT instrumented" not in out.stderr


def test_langgraph_reports_its_gap_with_the_reason():
    fakes.install_langgraph()
    fakes.install_langchain_core()
    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(agent_id="a", quiet=True)
    entry = next(r for r in manifest.found_unpatchable if r.framework == "langgraph")
    assert "nodes are callables YOU supply" in entry.detail
    # ... and it knows the tool boundary IS covered, because langchain_core was.
    assert "Tool calls ARE covered" in entry.detail


def test_langgraph_says_so_when_nothing_at_all_is_covered():
    fakes.install_langgraph()
    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(agent_id="a", quiet=True)
    entry = next(r for r in manifest.found_unpatchable if r.framework == "langgraph")
    assert "NO instrumented boundary at all" in entry.detail


# ═══════════════════════════════════════════════════════════════════════
# C4 — idempotent
# ═══════════════════════════════════════════════════════════════════════


def test_double_protect_does_not_double_wrap(cap):
    tools = fakes.install_langchain_core()

    first = _protect(reporter=cap)
    wrapper_after_first = tools.BaseTool.run
    assert is_xaidr_wrapper(wrapper_after_first)

    second = _protect(reporter=cap)
    assert tools.BaseTool.run is wrapper_after_first, "protect() re-wrapped a patched site"
    assert all(r.already_patched for r in second.patched)
    assert second._sites == [], "a no-op call must record nothing to undo"
    assert any("ALREADY instrumented" in n for n in second.notes), second.notes
    first.unprotect()


def test_double_protect_scans_a_call_exactly_once(cap, wait_events):
    """Proof by telemetry, not by identity: one tool call, one event."""
    tools = fakes.install_langchain_core()
    _protect(reporter=cap)
    _protect(reporter=cap)

    tool = tools.BaseTool("lookup", lambda x: f"got {x}")
    assert tool.run("a customer record") == "got a customer record"

    wait_events(cap, 1)
    tool_events = [e for e in cap.events if e["data"].get("toolName") == "lookup"]
    assert len(tool_events) == 1, tool_events


def test_a_third_protect_after_a_new_import_adds_only_the_new_sites():
    """The supported answer to 'a framework was imported after protect()'."""
    fakes.install_langchain_core()
    scope = ["langchain_core", "crewai"]
    first = _protect(targets=scope)
    assert {r.framework for r in first.patched} == {"langchain_core"}

    fakes.install_crewai()
    second = _protect(targets=scope)
    fresh = [r for r in second.patched if not r.already_patched]
    assert {r.framework for r in fresh} == {"crewai"}
    assert crewai_hook_registered()


def test_protect_tools_is_idempotent_too(cap, wait_events):
    """Part 4d: the same tool wrapped twice by protect_tools scans once."""
    sensor = xaidr.Sensor(agent_id="pt", reporter=cap)

    def send_email(body):
        return f"sent: {body}"

    once = sensor.protect_tools([send_email])
    twice = sensor.protect_tools(once)
    assert twice[0] is once[0], "protect_tools re-wrapped an already-wrapped tool"

    assert twice[0]("quarterly numbers") == "sent: quarterly numbers"
    wait_events(cap, 1)
    assert len([e for e in cap.events if e["data"].get("toolName") == "send_email"]) == 1


# ═══════════════════════════════════════════════════════════════════════
# The ONE path CrewAI's hook does not see, and what covers it instead
# ═══════════════════════════════════════════════════════════════════════


def test_protect_does_not_cover_a_direct_crewai_tool_run():
    """A bare ``tool.run()`` is not an agent boundary, and protect() says so.

    CrewAI dispatches ``before_tool_call`` from its executors. Developer code
    calling the tool object itself goes through none of them, so the hook does
    not fire — and this test exists so that stays a KNOWN, stated limit rather
    than a discovered one. The manifest entry names it; ``protect_tools`` (next
    test) is the answer.
    """
    crewai = fakes.install_crewai()
    manifest = _protect(targets=["crewai"], enforcement_mode="block")
    tool_record = next(r for r in manifest.patched if r.boundary == "tool")
    assert "Does NOT cover a direct tool.run()" in tool_record.detail
    assert "protect_tools" in tool_record.detail

    executed = []
    tool = crewai.tools.BaseTool("run_command", lambda **kw: executed.append(kw))
    tool.run(command="rm -rf / --no-preserve-root")
    assert executed, "the direct path is expected to run — the hook is not on it"


def test_a_second_protect_does_not_register_the_crewai_hook_twice(cap, wait_events):
    """Rule 4 for a registry, proved by telemetry rather than by identity.

    A registered hook has no ``__xaidr_patch__`` token to check, so idempotency
    is tracked separately — and the way that goes wrong is a SECOND hook that
    scans the same call again and emits a second event, making counts lie.
    """
    crewai = fakes.install_crewai()
    first = _protect(targets=["crewai"], reporter=cap)
    second = _protect(targets=["crewai"], reporter=cap)

    assert [r.already_patched for r in second.patched
            if r.boundary == "tool"] == [True]
    assert len(crewai.hooks.get_before_tool_call_hooks()) == 1

    tool = crewai.tools.BaseTool("lookup", lambda **kw: "ok")
    crew = crewai.Crew(tool_calls=[(tool, {"query": "a customer record"})])
    crew.kickoff()
    assert crew.tool_results == ["ok"]

    wait_events(cap, 1)
    tool_events = [e for e in cap.events if e["data"].get("toolName") == "lookup"]
    assert len(tool_events) == 1, tool_events

    # And the FIRST manifest still owns the teardown, so unprotecting it is
    # what removes the hook.
    second.unprotect()
    assert len(crewai.hooks.get_before_tool_call_hooks()) == 1
    first.unprotect()
    assert crewai.hooks.get_before_tool_call_hooks() == []


# ═══════════════════════════════════════════════════════════════════════
# unprotect / the returned handle
# ═══════════════════════════════════════════════════════════════════════


def test_unprotect_restores_every_original_by_identity():
    tools = fakes.install_langchain_core()
    crewai = fakes.install_crewai()
    originals = {
        "lc_run": tools.BaseTool.run,
        "lc_arun": tools.BaseTool.arun,
        "kickoff": crewai.Crew.kickoff,
    }
    manifest = _protect()
    assert manifest.is_active
    assert crewai_hook_registered(), "the CrewAI tool hook was never registered"
    restored = manifest.unprotect()

    assert tools.BaseTool.run is originals["lc_run"]
    assert tools.BaseTool.arun is originals["lc_arun"]
    assert crewai.Crew.kickoff is originals["kickoff"]
    # Reversal covers the registry hook too, not just patched attributes.
    assert not crewai_hook_registered(), "unprotect() left the CrewAI hook behind"
    assert not crewai.hooks.get_before_tool_call_hooks()
    assert not crewai.hooks.get_after_tool_call_hooks()
    assert len(restored) == len(manifest.patched)
    assert not manifest.is_active


def test_unprotect_is_safe_to_call_twice():
    fakes.install_langchain_core()
    manifest = _protect()
    assert manifest.unprotect()
    assert manifest.unprotect() == []
    assert xaidr.unprotect() == []


def test_module_level_unprotect_reverses_every_handle():
    tools = fakes.install_langchain_core()
    original = tools.BaseTool.run
    _protect(targets=["langchain_core"])
    fakes.install_crewai()
    _protect(targets=["crewai"])
    assert len(active_manifests()) == 2

    xaidr.unprotect()
    assert tools.BaseTool.run is original
    assert active_manifests() == []


def test_unprotect_leaves_a_site_someone_else_patched_over(capsys):
    """Silently uninstalling a third party's instrumentation would be worse."""
    tools = fakes.install_langchain_core()
    manifest = _protect(targets=["langchain_core"])

    ours = tools.BaseTool.run

    def someone_elses_apm(self, tool_input, **kwargs):
        return ours(self, tool_input, **kwargs)

    tools.BaseTool.run = someone_elses_apm

    restored = manifest.unprotect()
    assert tools.BaseTool.run is someone_elses_apm, "we clobbered a third-party patch"
    assert "BaseTool.run" not in " ".join(restored)
    assert "patched over by someone else" in capsys.readouterr().err
    tools.BaseTool.run = ours  # let the autouse fixture unwind cleanly


def test_the_handle_exposes_the_sensor_for_the_boundaries_it_cannot_reach():
    """Part 3d: protect() does boundaries; everything else stays on the sensor."""
    manifest = _protect(enforcement_mode="block", blocked_tools=["wire_transfer"])
    assert manifest.sensor.agent_id == "protect-test"
    assert manifest.sensor.enforcement_mode == "block"
    # The escape hatch the manifest points at for unpatchable tool boundaries.
    wrapped = manifest.sensor.protect_tools([lambda x: x])
    assert callable(wrapped[0])


def test_sensor_kwargs_pass_straight_through_and_nothing_extra_is_wired():
    """Boundaries only: no telemetry / policy / breaker decisions taken here."""
    from xaidr import CircuitBreaker

    breaker = CircuitBreaker(violation_threshold=3, violation_window_sec=60.0)
    manifest = _protect(enforcement_mode="block", circuit_breaker=breaker)
    assert manifest.sensor._breaker is not None
    # ...and without one, the feature stays entirely off — protect() did not
    # decide to turn it on for you.
    manifest.unprotect()
    plain = _protect(enforcement_mode="block")
    assert plain.sensor._breaker is None


def test_passing_an_existing_sensor_reuses_it():
    sensor = xaidr.Sensor(agent_id="mine", enforcement_mode="block")
    manifest = _protect(agent_id="ignored", sensor=sensor, policy_file="ignored.yaml")
    assert manifest.sensor is sensor
    assert manifest.agent_id == "mine"
    assert any("IGNORED" in n for n in manifest.notes)


# ═══════════════════════════════════════════════════════════════════════
# Part 4 — the failure modes that matter
# ═══════════════════════════════════════════════════════════════════════


def test_4a_a_framework_at_an_unexpected_version_is_reported_not_fatal():
    """An SDK whose entrypoint moved: manifest says so, everything else runs."""
    fakes.install_openai_agents(with_runner=False)
    tools = fakes.install_langchain_core()

    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(agent_id="a", quiet=True)

    bad = [r for r in manifest.found_unpatchable if r.framework == "openai-agents"]
    assert bad and "unexpected version layout" in bad[0].detail
    # The neighbouring framework is unaffected.
    assert is_xaidr_wrapper(tools.BaseTool.run)
    # And the half-patched framework still works.
    import agents

    assert agents.FunctionTool("x", lambda *_: None).name == "x"


def test_a_module_that_merely_shares_a_name_is_not_mistaken_for_a_framework():
    """`agents` is a name anyone might use for their own package.

    Claiming it is the OpenAI Agents SDK and then warning that it is unprotected
    would be a false alarm — and false alarms are exactly how a loud manifest
    stops being read.
    """
    import types

    sys.modules["agents"] = types.ModuleType("agents")  # somebody's own module
    manifest = _protect()
    assert "openai-agents" in manifest.not_present
    assert not any(r.framework == "openai-agents" for r in manifest.found_unpatchable)


def test_4b_a_framework_imported_after_protect_is_not_patched_and_says_so():
    manifest = _protect()
    assert "crewai" in manifest.not_present
    assert any("no import hook" in n for n in manifest.notes)
    assert any("call xaidr.protect() again" in n for n in manifest.notes)

    crewai = fakes.install_crewai()
    assert not crewai_hook_registered(), (
        "a late import was instrumented — an import hook must not have been installed"
    )
    assert not is_xaidr_wrapper(crewai.Crew.kickoff), (
        "a late import was patched — an import hook must not have been installed"
    )


def test_4c_a_patcher_that_raises_never_reaches_the_host(monkeypatch, capsys):
    import xaidr.autopatch.frameworks as fw

    def exploding(ctx):
        raise RuntimeError("the framework's own __getattr__ blew up")

    target = fw.FrameworkTarget("httpx", ("httpx",), exploding, "egress")
    monkeypatch.setattr("xaidr.autopatch.TARGETS", (target,))
    import httpx  # noqa: F401

    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(agent_id="a", quiet=True)

    assert manifest.patched == []
    entry = manifest.found_unpatchable[0]
    assert "RuntimeError" in entry.detail and "blew up" in entry.detail
    assert "NOT instrumented" in capsys.readouterr().err


def test_4c_a_broken_dispatcher_is_recorded_not_raised(monkeypatch, capsys):
    """Even a bug in protect()'s OWN loop must not take the host down."""
    class Hostile:
        def __iter__(self):
            raise RuntimeError("dispatcher bug")

    monkeypatch.setattr("xaidr.autopatch.TARGETS", Hostile())
    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(agent_id="a", quiet=True)
    assert manifest.error and "dispatcher bug" in manifest.error
    assert "instrumented nothing" in capsys.readouterr().err


def test_4c_a_caller_config_error_raises_by_default():
    """Your typo is not the environment's drift.

    A control that silently is not running because `enforcement_mode="blcok"`
    was misspelled is the worst outcome available, so this one raises — the same
    ADV-2 loudness Sensor() itself applies.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", XaidrProtectionWarning)
        with pytest.raises(ValueError, match="enforcement_mode"):
            xaidr.protect(agent_id="a", enforcement_mode="blcok", quiet=True)


def test_4c_the_strict_never_raise_mode_is_available(capsys):
    with pytest.warns(XaidrProtectionWarning):
        manifest = xaidr.protect(
            agent_id="a", enforcement_mode="blcok",
            raise_on_config_error=False, quiet=True,
        )
    assert manifest.patched == []
    assert "enforcement_mode" in manifest.error
    assert "instrumented nothing" in capsys.readouterr().err


def test_4d_protect_and_a_manual_protect_tools_agree_on_the_verdict(cap, wait_events):
    """Both layers over one tool: blocked once, and the block still holds."""
    tools = fakes.install_langchain_core()
    manifest = _protect(enforcement_mode="block", reporter=cap)

    def run_command(command):
        raise AssertionError("the tool executed despite a block")

    tool = tools.BaseTool("run_command", run_command)
    # The autopatched class seam AND an explicit protect_tools wrapper.
    doubly = manifest.sensor.protect_tools([tool])[0]

    out = doubly.run({"command": "rm -rf / --no-preserve-root"})
    assert "[BLOCKED]" in out
    wait_events(cap, 1)
    events = [e for e in cap.events if e["data"].get("toolName") == "run_command"]
    assert all(e["data"]["action"] == "blocked" for e in events), events


def test_targets_allowlist_skips_the_rest_without_claiming_coverage():
    fakes.install_langchain_core()
    fakes.install_crewai()
    manifest = _protect(targets=["crewai"])
    assert {r.framework for r in manifest.patched} == {"crewai"}
    assert "langchain_core" not in [r.framework for r in manifest.patched]


def test_an_unknown_target_name_is_reported():
    manifest = _protect(targets=["not-a-framework"])
    assert any("does not know about" in n for n in manifest.notes)


def test_default_agent_id_is_flagged_not_hidden():
    manifest = xaidr.protect(quiet=True)
    try:
        assert manifest.agent_id == "xaidr-protected-agent"
        assert any("agent_id was not set" in n for n in manifest.notes)
    finally:
        manifest.unprotect()
