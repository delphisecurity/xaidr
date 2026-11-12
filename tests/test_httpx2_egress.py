"""httpx2 egress under ``protect()`` and ``protect_http``: the httpx contract, on httpx2.

The current OpenAI (3.x), Anthropic (2.x) and MCP (2.x) Python SDKs send over
``httpx2``, a separate package whose ``Client`` is not ``httpx.Client``. xaidr
patches ``httpx2.Client.send`` and ``httpx2.AsyncClient.send`` with the same
wrapper it puts on httpx's, so one hook runs on both: the destination check, the
scan of the request's own bytes, then the S14 headers, then the send; the
response is scanned unless the caller streams it or ``ProtectedHttpClient``
scans it itself.

Every contract below is parametrised over ``httpx`` and ``httpx2`` and asserted
with one body. A family skips only where its package is not installed.

Installed lazily: ``protect()`` never imports httpx2. When httpx2 is installed
but not yet imported, ``protect()`` arms an import hook for that one name and
patches it when it is imported; ``unprotect()`` disarms the hook. When httpx2 is
not installed, nothing is armed. Those cases run in a subprocess, because this
process imports httpx2 at collection.

Inputs: committed corpus rows and plain benign text. No attack string.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import textwrap

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr import attestation as _att
from xaidr.autopatch import exempt
from xaidr.autopatch.core import is_xaidr_wrapper

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASI = os.path.join(ROOT, "asi_battery", "attacks.jsonl")
URL = "https://h.example/agents/peer/x"
FAMILIES = ("httpx", "httpx2")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


class _Record(SensorExtension):
    name = "record-attest"

    def __init__(self, headers=None):
        self.views = []
        self._headers = headers if headers is not None else {"x-delphi-attestation": "demo"}

    def attest_egress(self, view):
        self.views.append(view)
        return dict(self._headers)


@pytest.fixture(params=FAMILIES)
def hx(request):
    """The HTTP client package under test: httpx, then httpx2."""
    return pytest.importorskip(request.param)


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _sensor(extensions=(), **kw):
    sink = _Sink()
    s = Sensor(agent_id="httpx2-egress", reporter=sink, extensions=list(extensions), **kw)
    return s, sink


def _protect(sensor, hx):
    return xaidr.protect(sensor=sensor, targets=[hx.__name__], quiet=True)


def _b64u_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _client(hx, sent, response=None, **kw):
    """A client whose transport records (method, url, headers, body) per hop."""
    def handler(request):
        sent.append((request.method, str(request.url), dict(request.headers), request.read()))
        if response is not None:
            return response(request)
        return hx.Response(200, json={})
    return hx.Client(transport=hx.MockTransport(handler), **kw)


def _events(sensor, sink, direction):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == direction]


def _battery_text(sensor_check):
    """The first committed ASI battery text a block sensor refuses by ``sensor_check``."""
    if not os.path.isfile(ASI):
        pytest.skip("asi_battery/ is not in the sdist")
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    with open(ASI, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if sensor_check(probe, row):
                return row["text"]
    pytest.skip("no committed battery row matches")   # pragma: no cover


def _a2a_blocked_text():
    return _battery_text(lambda p, r: r["boundary"] in ("input", "a2a")
                         and p.scan_a2a(r["text"], destination="peer").action == "blocked")


def _output_blocked_text():
    return _battery_text(lambda p, r: r["boundary"] == "output"
                         and p.scan_output(r["text"]).action == "blocked")


# ── the seam is installed ────────────────────────────────────────────────────

def test_protect_patches_the_send_seam_of_each_family(hx):
    s, _ = _sensor()
    m = _protect(s, hx)
    name = hx.__name__
    targets = {r.target for r in m.patched if not r.already_patched}
    assert {f"{name}.Client.send", f"{name}.AsyncClient.send"} <= targets, (
        f"protect() did not instrument {name}: its traffic leaves the process unscanned "
        f"(patched={sorted(targets)}, unpatchable={[r.target for r in m.found_unpatchable]})")
    assert is_xaidr_wrapper(hx.Client.send) and is_xaidr_wrapper(hx.AsyncClient.send)
    xaidr.unprotect()
    assert not is_xaidr_wrapper(hx.Client.send), "unprotect() left the send seam patched"


# ── scan, then headers, then send ────────────────────────────────────────────

def test_a_post_is_scanned_then_attested_then_sent(hx):
    order = []

    class _Ordered(_Record):
        def attest_egress(self, view):
            order.append(("attest", len(_events(s, sink, "a2a"))))
            return super().attest_egress(view)

    rec = _Ordered()
    s, sink = _sensor([rec])
    _protect(s, hx)
    sent = []
    with _client(hx, sent) as c:
        c.post(URL, json={"message": "hello there friend"})
    a2a = _events(s, sink, "a2a")
    assert len(a2a) == 1, (
        f"an {hx.__name__} POST under protect() produced {len(a2a)} a2a scan events, not 1: "
        "its body was not scanned at egress")
    assert order == [("attest", 1)], "the attestation ran before the request's own scan"
    assert len(sent) == 1 and sent[0][2].get("x-delphi-attestation") == "demo", (
        "the S14 header did not reach the wire")
    view = rec.views[0]
    assert view.method == "POST" and view.host == "h.example"
    assert view.body_sha256 == _b64u_sha256(sent[0][3]), (
        "the attested digest does not name the bytes that left")
    assert [sc.scan_id for sc in view.scans] == [a2a[0]["scanId"]], (
        "the attestation names a scan other than this request's own")


def test_one_scan_and_one_attestation_cover_every_redirect_hop(hx):
    rec = _Record()
    s, sink = _sensor([rec])
    _protect(s, hx)
    sent = []

    def respond(request):
        if request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://h.example/agents/peer/y"})
        return hx.Response(200, json={})

    with _client(hx, sent, respond, follow_redirects=True) as c:
        c.post(URL, json={"message": "hello there friend"})
    assert [u for _, u, _, _ in sent] == [URL, "https://h.example/agents/peer/y"]
    scans, views = len(_events(s, sink, "a2a")), len(rec.views)
    assert (scans, views) == (1, 1), (
        f"one client-level {hx.__name__} send across a redirect was scanned {scans} times and "
        f"attested {views} times; it must be exactly once each")
    assert all(h.get("x-delphi-attestation") == "demo" for _, _, h, _ in sent), (
        "a redirect hop left without the attestation the send carried")


def test_a_refused_body_never_leaves_and_is_not_attested(hx):
    text = _a2a_blocked_text()
    rec = _Record()
    s, _ = _sensor([rec], enforcement_mode="block")
    _protect(s, hx)
    sent = []
    with _client(hx, sent) as c, pytest.raises(DelphiBlockedError):
        c.post(URL, json={"message": text})
    assert sent == [], f"a body a block sensor refuses left over {hx.__name__}"
    assert rec.views == []


def test_a_denied_destination_is_refused_on_every_verb(hx):
    s, _ = _sensor(enforcement_mode="block")
    s.block_urls(["denied.example"])
    _protect(s, hx)
    sent = []
    with _client(hx, sent) as c:
        for call in (lambda: c.get("https://denied.example/x"),
                     lambda: c.delete("https://denied.example/x"),
                     lambda: c.post("https://denied.example/x", json={"message": "hello there"})):
            with pytest.raises(DelphiBlockedError):
                call()
    assert sent == [], f"a request to a denied destination left over {hx.__name__}"


def test_a_response_is_scanned_and_a_refused_one_raises(hx):
    text = _output_blocked_text()
    s, sink = _sensor(enforcement_mode="block")
    _protect(s, hx)
    with _client(hx, [], lambda r: hx.Response(200, json={"message": text})) as c:
        with pytest.raises(DelphiBlockedError):
            c.get(URL)
    blocked = [e for e in _events(s, sink, "output") if e["action"] == "blocked"]
    assert len(blocked) == 1, f"an {hx.__name__} response was not scanned for output DLP"


def test_an_exempt_client_is_not_scanned_and_its_neighbour_is(hx):
    s, sink = _sensor()
    _protect(s, hx)
    with exempt(_client(hx, [])) as c:
        c.post(URL, json={"message": "hello there friend"})
    assert _events(s, sink, "a2a") == [], f"an exempt {hx.__name__} client was scanned"
    with _client(hx, []) as c:
        c.post(URL, json={"message": "hello there friend"})
    assert len(_events(s, sink, "a2a")) == 1, (
        f"a {hx.__name__} client that is not exempt was not scanned either")


def test_no_attesting_extension_means_no_digest_and_no_header(hx, monkeypatch):
    calls = []
    real = _att._body_sha256
    monkeypatch.setattr(_att, "_body_sha256", lambda data: calls.append(1) or real(data))
    plain, guarded = [], []
    with _client(hx, plain) as c:
        c.post(URL, json={"message": "hello there friend"})
    s, sink = _sensor()
    _protect(s, hx)
    with _client(hx, guarded) as c:
        c.post(URL, json={"message": "hello there friend"})
    assert len(_events(s, sink, "a2a")) == 1, f"an {hx.__name__} POST under protect() was not scanned"
    assert calls == [], "a sensor with no S14 extension paid for a digest"
    assert guarded[0][2] == plain[0][2], "protect() changed the headers of an unattested request"


# ── protect_http over each family ────────────────────────────────────────────

def test_protect_http_scans_and_attests_a_body_verb(hx):
    rec = _Record()
    s, sink = _sensor([rec])
    sent = []
    s.protect_http(_client(hx, sent)).post(URL, json={"message": "hello there é"})
    assert len(_events(s, sink, "a2a")) == 1, f"protect_http over {hx.__name__} did not scan the body"
    assert sent[0][2].get("x-delphi-attestation") == "demo"
    assert rec.views[0].body_sha256 == _b64u_sha256(sent[0][3]), (
        "protect_http attested a digest of bytes other than the ones that left")


def test_protect_http_with_protect_scans_and_attests_once(hx):
    rec = _Record()
    s, sink = _sensor([rec])
    _protect(s, hx)
    sent = []
    s.protect_http(_client(hx, sent)).post(URL, json={"message": "hello there friend"})
    a2a = _events(s, sink, "a2a")
    assert len(a2a) == 1, f"one protect_http request over {hx.__name__} was scanned {len(a2a)} times"
    assert len(rec.views) == 1 and len(sent) == 1
    assert list(sent[0][2]).count("x-delphi-attestation") == 1


@pytest.mark.parametrize("verb", ("get", "delete"))
def test_protect_http_get_and_delete_responses_are_scanned_at_the_send_seam(hx, verb):
    text = _output_blocked_text()
    s, sink = _sensor(enforcement_mode="block")
    _protect(s, hx)
    client = s.protect_http(_client(hx, [], lambda r: hx.Response(200, json={"message": text})))
    with pytest.raises(DelphiBlockedError):
        getattr(client, verb)(URL)
    blocked = [e["direction"] for e in _events(s, sink, "output") if e["action"] == "blocked"]
    assert blocked == ["output"], (
        f"a {verb.upper()} response through protect_http over {hx.__name__} was not scanned")


# ── in a fresh interpreter: when httpx2 is imported, installed, or neither ────

_PRELUDE = textwrap.dedent('''
    import sys
    {block}
    import xaidr
    from xaidr import Sensor, SensorExtension
    from xaidr.autopatch.core import is_xaidr_wrapper

    class Sink:
        def __init__(self): self.events = []
        def report(self, batch): self.events.extend(batch)
        def close(self): pass

    class Rec(SensorExtension):
        name = "rec"
        def __init__(self): self.views = []
        def attest_egress(self, view):
            self.views.append(view)
            return {{"x-delphi-attestation": "demo"}}

    def hooks():
        return [f for f in sys.meta_path if type(f).__module__.startswith("xaidr")]

    def ours():
        """The ARMED xaidr import hooks (a disarmed one stays, inert)."""
        return [f for f in hooks() if f.armed]

    sink, rec = Sink(), Rec()
    sensor = Sensor(agent_id="child", reporter=sink, extensions=[rec])
''')


def _child(body: str, *, block: str = "", flags=()) -> str:
    code = _PRELUDE.format(block=block) + textwrap.dedent(body)
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run([sys.executable, *flags, "-c", code], capture_output=True,
                         text=True, env=env, cwd=ROOT, timeout=120)
    assert out.returncode == 0, f"child failed:\nSTDOUT:\n{out.stdout}\nSTDERR:\n{out.stderr}"
    return out.stdout


def test_httpx2_imported_after_protect_is_patched_when_it_is_imported():
    pytest.importorskip("httpx2")
    out = _child('''
        assert "httpx2" not in sys.modules
        m = xaidr.protect(sensor=sensor, quiet=True)
        assert "httpx2" not in sys.modules, "protect() imported httpx2"
        assert "httpx2" in m.not_present
        assert len(ours()) == 1, (
            f"protect() armed {len(ours())} import hooks for an installed, not-yet-imported "
            "httpx2 (expected 1): httpx2 imported later would leave the process unscanned")
        import httpx2
        assert is_xaidr_wrapper(httpx2.Client.send), (
            "httpx2 imported after protect() was left unpatched: its traffic leaves unscanned")
        assert is_xaidr_wrapper(httpx2.AsyncClient.send)
        assert ours() == [], "the import hook stayed armed after it fired"
        assert len(hooks()) == 1
        sent = []
        def handler(request):
            sent.append(dict(request.headers))
            return httpx2.Response(200, json={})
        with httpx2.Client(transport=httpx2.MockTransport(handler)) as c:
            c.post("https://h.example/agents/peer/x", json={"message": "hello there friend"})
        sensor.flush()
        a2a = [e for e in sink.events if e["data"].get("direction") == "a2a"]
        assert len(a2a) == 1 and sent[0]["x-delphi-attestation"] == "demo"
        assert {"httpx2.Client.send", "httpx2.AsyncClient.send"} <= {r.target for r in m.patched}
        assert "httpx2" not in m.not_present
        xaidr.unprotect()
        assert not is_xaidr_wrapper(httpx2.Client.send)
        print("lazy-ok")
    ''')
    assert "lazy-ok" in out


def test_unprotect_before_the_import_disarms_the_hook():
    pytest.importorskip("httpx2")
    out = _child('''
        m = xaidr.protect(sensor=sensor, quiet=True)
        assert len(ours()) == 1, f"expected one armed import hook for httpx2, found {len(ours())}"
        xaidr.unprotect()
        assert ours() == [], "unprotect() left the httpx2 import hook armed"
        assert len(hooks()) == 1
        import httpx2
        assert not is_xaidr_wrapper(httpx2.Client.send), "a disarmed hook still patched httpx2"
        print("disarm-ok")
    ''')
    assert "disarm-ok" in out


def test_a_second_protect_arms_no_second_hook():
    pytest.importorskip("httpx2")
    out = _child('''
        xaidr.protect(sensor=sensor, quiet=True)
        second = xaidr.protect(sensor=sensor, quiet=True)
        assert len(ours()) == 1, (
            f"{len(ours())} import hooks armed for httpx2 after two protect() calls "
            "(expected exactly 1: none leaves httpx2 unpatched, two wrap it twice)")
        import httpx2
        assert is_xaidr_wrapper(httpx2.Client.send)
        assert not is_xaidr_wrapper(httpx2.Client.send.__xaidr_original__), "httpx2 was wrapped twice"
        xaidr.unprotect()
        assert not is_xaidr_wrapper(httpx2.Client.send) and ours() == []
        assert len(hooks()) == 1, f"{len(hooks())} hook objects for one module name"
        print("once-ok")
    ''')
    assert "once-ok" in out


def test_httpx2_not_installed_arms_nothing_and_imports_nothing():
    """``-S``: no site-packages, so httpx2 is genuinely not installed in the child."""
    out = _child('''
        import importlib.util
        assert importlib.util.find_spec("httpx2") is None
        m = xaidr.protect(sensor=sensor, quiet=True)
        assert hooks() == [], "an import hook was inserted for a package that is not installed"
        assert "httpx2" in m.not_present, m.not_present
        assert "httpx2" not in sys.modules, "protect() imported httpx2"
        assert not any("httpx2" in n for n in m.notes), m.notes
        print("absent-ok")
    ''', flags=("-S",))
    assert "absent-ok" in out


def test_protect_http_over_httpx2_without_httpx_installed():
    """With httpx 0.x absent (the current SDKs do not install it), an attesting
    sensor's protect_http over an httpx2 client builds its digest from the
    httpx2 request; it must not reach for httpx."""
    pytest.importorskip("httpx2")
    out = _child('''
        import base64, hashlib, httpx2
        sent = []
        def handler(request):
            sent.append((dict(request.headers), request.read()))
            return httpx2.Response(200, json={})
        c = sensor.protect_http(httpx2.Client(transport=httpx2.MockTransport(handler)))
        c.post("https://h.example/agents/peer/x", json={"message": "hello there é"})
        digest = base64.urlsafe_b64encode(hashlib.sha256(sent[0][1]).digest()).rstrip(b"=").decode()
        assert sent[0][0]["x-delphi-attestation"] == "demo"
        assert rec.views[0].body_sha256 == digest
        assert "httpx" not in sys.modules or sys.modules["httpx"] is None
        print("nohttpx-ok")
    ''', block='sys.modules["httpx"] = None')
    assert "nohttpx-ok" in out


def test_alias_httpx_is_one_wrapper_and_one_scan():
    """``httpx2.alias_httpx()`` makes ``import httpx`` return httpx2: the httpx
    target patches httpx2's send and the httpx2 target finds it patched."""
    pytest.importorskip("httpx2")
    out = _child('''
        import httpx2
        httpx2.alias_httpx()
        import httpx
        assert httpx is httpx2
        m = xaidr.protect(sensor=sensor, quiet=True)
        recs = {(r.framework, r.target, r.already_patched) for r in m.patched}
        assert ("httpx", "httpx.Client.send", False) in recs, recs
        assert ("httpx2", "httpx2.Client.send", True) in recs, recs
        assert not is_xaidr_wrapper(httpx2.Client.send.__xaidr_original__)
        with httpx2.Client(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={}))) as c:
            c.post("https://h.example/agents/peer/x", json={"message": "hello there friend"})
        sensor.flush()
        assert len([e for e in sink.events if e["data"].get("direction") == "a2a"]) == 1
        print("alias-ok")
    ''')
    assert "alias-ok" in out


# ── the import hook under the conditions a host can create ───────────────────

def test_import_xaidr_loads_no_import_machinery():
    """``import xaidr`` costs every host the same modules it did before httpx2:
    the hook needs neither ``importlib.abc`` nor ``importlib.util``."""
    out = _child('''
        print(sorted(m for m in ("importlib.abc", "importlib.util", "importlib.resources")
                     if m in sys.modules))
    ''', flags=("-I",), block=f"sys.path.insert(0, {ROOT!r})")
    assert out.strip().splitlines()[-1] == "[]", (
        f"import xaidr now imports {out.strip().splitlines()[-1]} on every host")


def test_a_loader_shared_by_several_modules_patches_httpx2_once_it_has_run():
    """zipimport serves every module of an archive through one loader instance.
    The hook wraps that instance, so a dependency httpx2 imports while it runs
    goes through the same wrapper first; the patch must wait for httpx2 itself."""
    out = _child('''
        import importlib.machinery
        SOURCES = {
            "httpx2_dep": "VALUE = 1",
            "httpx2": "import httpx2_dep\\n"
                      "class Client:\\n    def send(self, request, **kw): return 'sent'\\n"
                      "class AsyncClient:\\n    async def send(self, request, **kw): return 'sent'\\n",
        }
        class Shared:
            def create_module(self, spec): return None
            def exec_module(self, module): exec(SOURCES[module.__name__], module.__dict__)
        LOADER = Shared()
        class Finder:
            def find_spec(self, name, path=None, target=None):
                if name in SOURCES:
                    return importlib.machinery.ModuleSpec(name, LOADER)
        sys.meta_path.insert(0, Finder())
        m = xaidr.protect(sensor=sensor, targets=["httpx2"], quiet=True)
        assert len(ours()) == 1, "nothing was armed for the archive's httpx2"
        import httpx2
        assert is_xaidr_wrapper(httpx2.Client.send), (
            "the hook fired on httpx2's dependency and patched a half-built httpx2: "
            f"httpx2 is left unpatched ({[r.detail for r in m.found_unpatchable]})")
        assert m.found_unpatchable == []
        print("shared-ok")
    ''')
    assert "shared-ok" in out


def test_disarming_while_another_import_walks_the_finders_skips_none():
    """``unprotect()`` can run while another thread's import is walking
    ``sys.meta_path``. Taking the hook OUT of the list then shifts the list under
    that walk, and the finder after the one being asked is skipped; the import
    fails. The hook stays in place, disarmed. A finder placed just before the
    path finder runs ``unprotect()`` in the middle of the walk."""
    pytest.importorskip("httpx2")
    out = _child('''
        import importlib.machinery
        xaidr.protect(sensor=sensor, quiet=True)
        assert len(ours()) == 1
        class Midwalk:
            def find_spec(self, name, path=None, target=None):
                if name == "colorsys":
                    xaidr.unprotect()
                return None
        at = next(i for i, f in enumerate(sys.meta_path) if f is importlib.machinery.PathFinder)
        sys.meta_path.insert(at, Midwalk())
        import colorsys
        assert ours() == []
        print("walk-ok")
    ''')
    assert "walk-ok" in out


def test_unprotect_during_the_deferred_patch_leaves_nothing_patched():
    """``unprotect()`` on one thread while another thread's ``import httpx2`` is
    applying the deferred patch: the patch must either not happen or be unwound,
    never left installed on a manifest that is already reverted."""
    pytest.importorskip("httpx2")
    out = _child('''
        import dataclasses, threading, time
        import xaidr.autopatch as ap
        from xaidr.autopatch import frameworks as fw
        in_apply, b_started = threading.Event(), threading.Event()
        real = fw._patch_httpx2
        def slow(ctx):
            in_apply.set()
            b_started.wait(5)
            time.sleep(0.2)          # the unprotect() below is under way
            real(ctx)
        targets = tuple(dataclasses.replace(t, apply=slow) if t.name == "httpx2" else t
                        for t in ap.TARGETS)
        ap.TARGETS = targets
        xaidr.protect(sensor=sensor, quiet=True)
        def importer():
            import httpx2
        def remover():
            in_apply.wait(5)
            b_started.set()
            xaidr.unprotect()
        a, b = threading.Thread(target=importer), threading.Thread(target=remover)
        a.start(); b.start(); a.join(10); b.join(10)
        import httpx2
        assert not is_xaidr_wrapper(httpx2.Client.send), (
            "unprotect() ran during the deferred patch and the patch stayed installed, "
            "with no active manifest left to remove it")
        print("race-ok")
    ''')
    assert "race-ok" in out


def test_a_second_protect_says_the_hook_is_armed_not_that_httpx2_is_left_out():
    pytest.importorskip("httpx2")
    out = _child('''
        xaidr.protect(sensor=sensor, quiet=True)
        second = xaidr.protect(sensor=sensor, quiet=True)
        contradiction = [n for n in second.notes if "UNINSTRUMENTED" in n and "except" not in n]
        assert not contradiction, (
            "a second protect() says everything under NOT PRESENT, httpx2 included, will be "
            f"uninstrumented, while the armed hook patches httpx2: {contradiction}")
        print("notes-ok")
    ''')
    assert "notes-ok" in out
