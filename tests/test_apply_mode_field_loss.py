"""FIXED: monitor-mode downgrade used to drop three ScanResult fields.

``_apply_mode`` reconstructs the ScanResult when it softens a halting verdict,
and it used to pass five of the dataclass's eight fields. ``input_status``,
``nano_score`` and ``nano_raw`` were silently dropped, so in MONITOR mode — the
default — a blocked verdict carrying nano readings or a not-scannable marker
returned them as ``None``.

WHY IT MATTERED. ``nano_score`` is how an operator tells a rules verdict from an
ML-assisted one, and ``input_status`` is how a caller's own bug stays visible
(see ``_emit_not_scannable``: fail open but RECORD). Both survived in block mode
and vanished in monitor mode, which is exactly backwards — monitor is the mode
you run while you are still measuring.

FOUND while building S1/S5/S6 and unrelated to them, so it is a separate commit
rather than folded in: the seams PR's headline claim is "no behaviour change
with no extension registered", and an observable change to what monitor mode
returns does not belong under that sentence.

THE FIX is ``dataclasses.replace`` instead of naming five of eight fields. That
is the durable form: constructing by field list re-breaks silently every time a
field is added to ScanResult, and this call site had already drifted twice.
"""

from xaidr import Sensor
from xaidr.types import ScanResult


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


def test_block_mode_keeps_the_fields_which_is_what_made_it_a_bug():
    """The discriminating half: the same verdict in block mode always kept them.

    This is what showed the loss was an artefact of the DOWNGRADE path rather
    than a field the sensor never populates, and it is why the fix belongs in
    ``_apply_mode`` and nowhere else.
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


def test_every_scanresult_field_survives_a_downgrade():
    """The regression guard that does not rot.

    The two tests above name the three fields that were actually lost. This one
    asserts the general property — a downgrade changes ``action`` and NOTHING
    else — so a field added to ScanResult tomorrow is covered without anyone
    remembering to come back here. That is the failure mode the original bug
    had: a call site that construct-by-field-list silently excluded.
    """
    import dataclasses

    s = Sensor(agent_id="field-loss-all", enforcement_mode="monitor")
    before = ScanResult(
        action="blocked", score=0.9, category="prompt_injection", rules=["R"],
        latency_ms=3, input_status="not_scannable", nano_score=0.77, nano_raw=0.88,
    )
    after = s._apply_mode(before)

    assert after.action == "flagged"
    for field in dataclasses.fields(ScanResult):
        if field.name == "action":
            continue
        assert getattr(after, field.name) == getattr(before, field.name), (
            f"downgrade changed {field.name!r}, which is not the action"
        )
