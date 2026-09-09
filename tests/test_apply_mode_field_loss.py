"""FOUND, NOT FIXED: monitor-mode downgrade drops three ScanResult fields.

``_apply_mode`` reconstructs the ScanResult when it softens a halting verdict,
and it passes five of the dataclass's eight fields. ``input_status``,
``nano_score`` and ``nano_raw`` are silently dropped, so in MONITOR mode — the
default — a blocked verdict that carried nano readings or a not-scannable marker
returns them as ``None``.

WHY IT MATTERS. ``nano_score`` is how an operator tells a rules verdict from an
ML-assisted one, and ``input_status`` is how a caller's own bug stays visible
(see ``_emit_not_scannable``: fail open but RECORD). Both survive in block mode
and vanish in monitor mode, which is exactly backwards — monitor is the mode you
run while you are still measuring.

NOT FIXED HERE ON PURPOSE. This was found while building S1/S5/S6 and is
unrelated to them: the fix is a one-line switch to ``dataclasses.replace``, but
it changes what a monitor-mode sensor returns, and folding an observable
behaviour change into a seams PR whose headline claim is "no behaviour change
with no extension registered" is how a real change hides inside a refactor. It
gets its own commit.

Marked xfail(strict=True) so it fails loudly the moment someone fixes it and
forgets to delete this file.
"""

import pytest

from xaidr import Sensor
from xaidr.types import ScanResult


@pytest.mark.xfail(strict=True, reason="known defect, fix tracked separately")
def test_monitor_downgrade_preserves_nano_and_input_status():
    s = Sensor(agent_id="field-loss", enforcement_mode="monitor")
    before = ScanResult(
        action="blocked", score=0.9, category="prompt_injection", rules=["R"],
        latency_ms=3, input_status="not_scannable", nano_score=0.77, nano_raw=0.88,
    )
    after = s._apply_mode(before)

    assert after.action == "flagged", "precondition: monitor softened the verdict"
    assert after.input_status == "not_scannable", (
        "monitor mode dropped input_status, so a caller's malformed-input bug "
        "becomes invisible in the mode people run while measuring"
    )
    assert after.nano_score == 0.77, "monitor mode dropped nano_score"
    assert after.nano_raw == 0.88, "monitor mode dropped nano_raw"


def test_block_mode_keeps_the_fields_which_is_what_makes_it_a_bug():
    """The discriminating half: the same verdict in block mode keeps everything.

    This is what shows the loss is an artefact of the downgrade path rather than
    a field the sensor never populates.
    """
    s = Sensor(agent_id="field-loss-block", enforcement_mode="block")
    before = ScanResult(
        action="blocked", score=0.9, category="prompt_injection", rules=["R"],
        latency_ms=3, input_status="not_scannable", nano_score=0.77, nano_raw=0.88,
    )
    after = s._apply_mode(before)
    assert after.action == "blocked"        # block mode: downgrade is identity
    assert after.input_status == "not_scannable"
    assert after.nano_score == 0.77
    assert after.nano_raw == 0.88
