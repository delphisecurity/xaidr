"""Batch A guards — BS1 destructive shell commands + BS4 generic-secret DLP.

BS1 extends the existing LLM08_shell_destructive rule (which already blocks rm -rf
/ mkfs) with chmod/dd/shred/wipefs/fork-bomb/redirect-overwrite, scoped to
DANGEROUS args/targets so normal dev operations (chmod 644, chmod +x ./script,
dd file-to-file) still pass.

BS4 extends output DLP: OpenAI sk- keys with hyphenated prefixes (sk-live-/
sk-proj-), and Luhn-validated payment cards (separator-tolerant). Luhn is the FP
guard — a non-Luhn 13-19 digit number (order ID, tracking number) is NOT a card.
"""

from __future__ import annotations

import pytest

from xaidr import Sensor

CAUGHT = ("flagged", "blocked")


@pytest.fixture
def block():
    return Sensor(agent_id="batch-a", enforcement_mode="block")


# ── BS1: destructive commands — BLOCK (tool-arg path AND scan path) ──────────
DESTRUCTIVE = [
    ("chmod-R-777", "chmod -R 777 /etc"),
    ("chmod-777-root", "chmod 777 /"),
    ("chmod-o+w-sys", "chmod o+w /etc/passwd"),
    ("dd-to-sda", "dd if=/dev/zero of=/dev/sda"),
    ("dd-to-nvme", "dd if=/dev/urandom of=/dev/nvme0n1 bs=1M"),
    ("mkfs", "mkfs.ext4 /dev/sda1"),
    ("shred-dev", "shred /dev/sda"),
    ("wipefs", "wipefs -a /dev/sdb"),
    ("fork-bomb", ":(){ :|:& };:"),
    ("redirect-dev", "echo x > /dev/sda"),
    ("rm-rf", "rm -rf /"),
]

# ── BS1: benign chmod/dd — must stay ALLOWED (the FP guard) ──────────────────
BENIGN_SHELL = [
    ("chmod-644", "chmod 644 myfile.txt"),
    ("chmod-+x-local", "chmod +x ./my-build-script.sh"),
    ("chmod-755-bin", "chmod 755 ./bin/tool"),
    ("dd-file-to-file", "dd if=./input.img of=./output.img"),
]


@pytest.mark.parametrize("label,cmd", DESTRUCTIVE, ids=[c[0] for c in DESTRUCTIVE])
def test_destructive_blocked_tool_path(block, label, cmd):
    r = block.scan_tool_call(tool_name="shell", arguments={"cmd": cmd})
    assert r.action == "blocked", f"{label}: not blocked on tool-arg path ({r.action} {r.score})"


@pytest.mark.parametrize("label,cmd", DESTRUCTIVE, ids=[c[0] for c in DESTRUCTIVE])
def test_destructive_blocked_scan_path(block, label, cmd):
    assert block.scan(cmd).action == "blocked", f"{label}: not blocked on scan path"


@pytest.mark.parametrize("label,cmd", BENIGN_SHELL, ids=[c[0] for c in BENIGN_SHELL])
def test_benign_shell_allowed(block, label, cmd):
    r = block.scan_tool_call(tool_name="shell", arguments={"cmd": cmd})
    assert r.action == "allowed", f"{label}: benign shell false-positive ({r.action} {r.rules})"
    assert block.scan(cmd).action == "allowed", f"{label}: benign shell FP on scan path"


# ── BS4: secrets in output — CAUGHT ──────────────────────────────────────────
SECRETS = [
    ("openai-sk-live", "the key is sk-live-abc123DEF456ghi789JKL012mno345 ok"),
    ("openai-sk-proj", "key sk-proj-abc123DEF456ghi789JKL012mno345xyz"),
    ("stripe-sk_live", "sk_live_abc123DEF456ghi789JKL012"),
    ("slack-xoxb", "xoxb-1234567890-ABCDEFGHIJKLMNOP"),
    ("card-visa-sp", "card 4242 4242 4242 4242"),
    ("card-visa", "4111111111111111"),
    ("card-mc", "5555555555554444"),
    ("card-amex", "378282246310005"),
    # no-regression on existing formats
    ("github", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
    ("ssn", "123-45-6789"),
    ("aws", "AKIAIOSFODNN7EXAMPLE"),
]

# ── BS4: benign — must stay ALLOWED (Luhn / non-key guards) ───────────────────
BENIGN_OUTPUT = [
    ("order-id-non-luhn", "order 1234567812345678 shipped"),
    ("visa-prefix-non-luhn", "ref 4111111111111112 done"),
    ("card-luhn-fail", "acct 4242424242424241"),
    ("uuid", "id 550e8400-e29b-41d4-a716-446655440000"),
    ("hash32-no-key-ctx", "sha 9f86d081884c7d659a2feaa0c55ad015"),
    ("date", "The meeting is at 3pm on 2024-01-15."),
]


@pytest.mark.parametrize("label,text", SECRETS, ids=[c[0] for c in SECRETS])
def test_secret_caught_in_output(block, label, text):
    assert block.scan_output(text).action in CAUGHT, f"{label}: secret not caught"


@pytest.mark.parametrize("label,text", BENIGN_OUTPUT, ids=[c[0] for c in BENIGN_OUTPUT])
def test_benign_output_allowed(block, label, text):
    r = block.scan_output(text)
    assert r.action == "allowed", f"{label}: benign output false-positive ({r.action} {r.rules})"


def test_luhn_gate_is_the_card_discriminator():
    from xaidr.scanner.dlp import _luhn_valid
    assert _luhn_valid("4242 4242 4242 4242")      # valid Visa test card
    assert not _luhn_valid("4242424242424241")     # one digit off → invalid
    assert not _luhn_valid("1234567812345678")     # order id → invalid
    assert not _luhn_valid("42424242")             # too short


def test_batch_a_patterns_redos_safe():
    import time
    from xaidr.scanner.l1 import scan_l1
    from xaidr.scanner.dlp import scan_dlp

    payloads = [
        "dd " + "x" * 200_000,
        "chmod " + "7" * 200_000,
        "4" + "2" * 200_000,
        "sk-" + "a-" * 100_000,
        "4242 " * 80_000,
    ]
    # CPU seconds, not wall clock. Same reasoning as every other time bound in
    # this suite (written out once, at tests/test_redos_pattern_audit.py): a
    # backtracking pattern burns CPU, and CPU is the clock a busy neighbour
    # cannot move. Budget unchanged.
    for p in payloads:
        t0 = time.process_time()
        scan_l1(p)
        scan_dlp(p)
        assert time.process_time() - t0 < 1.5, "Batch-A pattern too slow (possible ReDoS)"
