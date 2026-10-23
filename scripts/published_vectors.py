"""The published test vectors the value-origin differential reads.

    python scripts/published_vectors.py fetch DIR     download every source into DIR
                                                     and check it against its sha256
    python scripts/published_vectors.py extract DIR   write the vendored vector files
                                                     from the sources in DIR
    python scripts/published_vectors.py verify DIR    extract again and compare with
                                                     the vendored files, byte for byte

``tests/published_vectors/SOURCES.json`` names each source: where it comes from
(a tag or commit, never a branch), the sha256 of the file, its licence and the
licence file vendored beside the vectors. The vectors are extracted, never
hand-written:

* CPython's ``test_urlparse.py`` and email tests: every string literal with a
  ``:``, ``@``, ``/`` or ``.`` in it (an AST walk; run ``extract`` on the newest
  interpreter, which parses every version's file).
* curl's ``lib1560.c`` and Go's ``url_test.go`` and ``message_test.go``: every
  string literal, and the host or address each test table expects.
* IdnaTestV2 (the UTS-46 version the core pins, and the newest): every source
  framed as ``http://<source>/`` and ``user@<source>``, with toAsciiN as the
  expected host when its status carries no error under the core's flags. The
  pinned version's rows are also written on their own (``idna-<version>.jsonl``)
  for the conformance test.
* WPT's ``urltestdata.json`` (each input, with the hostname when it parses with
  no base and a special scheme fetch sends to) and ``toascii.json`` (each input
  as ``https://<input>/x``).

``extract`` and ``verify`` read only DIR; only ``fetch`` touches the network.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "published_vectors"
SOURCES = OUT / "SOURCES.json"
MAX_CHARS = 4000

#: The core's UTS-46 flags (docs/value-origin-rulings.md, S-4): an IdnaTestV2
#: status code from these steps is not an error for it.
IGNORED_IDNA_CODES = {"A4_1", "A4_2", "V2", "V3", "U1"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sources() -> list:
    return json.loads(SOURCES.read_text(encoding="utf-8"))["sources"]


def fetch(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    bad = 0
    for s in _sources():
        for f in [s] + s.get("licence_sources", []):
            req = urllib.request.Request(f["url"], headers={"User-Agent": "xaidr-vectors"})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
            got = _sha(body)
            (directory / f["file"]).write_bytes(body)
            if got != f["sha256"]:
                bad += 1
                print(f"MISMATCH {f['file']}: {got} != {f['sha256']}")
            else:
                print(f"ok {f['file']}")
    return 1 if bad else 0


# ── literals ─────────────────────────────────────────────────────────────────
def _keep(v: str) -> bool:
    return 0 < len(v) <= MAX_CHARS and any(c in v for c in ":@/.")


def python_literals(text: str) -> list:
    out = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, bytes):
                try:
                    v = v.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            if isinstance(v, str) and _keep(v):
                out.append(v)
    return out


_C_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'",
          "a": "\a", "b": "\b", "f": "\f", "v": "\v", "?": "?"}


def _c_unescape(body: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i:i + 1]
        if c != b"\\":
            out += c
            i += 1
            continue
        n = body[i + 1:i + 2].decode("latin-1")
        if n == "x":
            m = re.match(rb"[0-9A-Fa-f]{1,2}", body[i + 2:])
            out.append(int(m.group(0), 16))
            i += 2 + len(m.group(0))
        elif n.isdigit():
            m = re.match(rb"[0-7]{1,3}", body[i + 1:])
            out.append(int(m.group(0), 8) & 0xFF)
            i += 1 + len(m.group(0))
        else:
            out += _C_ESC.get(n, n).encode("latin-1")
            i += 2
    return out.decode("utf-8", "surrogateescape")


_C_TOKEN = re.compile(rb'//[^\n]*|/\*.*?\*/|"((?:[^"\\\n]|\\.)*)"|\'(?:[^\'\\\n]|\\.)*\'',
                      re.S)


def c_literals(raw: bytes) -> list:
    """Every C string literal, adjacent literals joined, in file order."""
    out, cur, last_end = [], None, None
    for m in _C_TOKEN.finditer(raw):
        if m.group(1) is None:
            continue
        s = _c_unescape(m.group(1))
        between = raw[last_end:m.start()] if last_end is not None else b"x"
        if cur is not None and not between.strip():
            cur += s
        else:
            if cur is not None:
                out.append(cur)
            cur = s
        last_end = m.end()
    if cur is not None:
        out.append(cur)
    return out


_GO_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"((?:[^"\\\n]|\\.)*)"|`([^`]*)`|\'(?:[^\'\\\n]|\\.)+\'',
                       re.S)


def _go_unescape(body: str) -> str:
    def esc(m):
        s = m.group(0)
        k = s[1]
        if k in "xuU":
            return chr(int(s[2:], 16)) if k != "x" else bytes([int(s[2:], 16)]).decode("latin-1")
        if k.isdigit():
            return bytes([int(s[1:], 8)]).decode("latin-1")
        return _C_ESC.get(k, k)
    s = re.sub(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{3}|.)", esc, body)
    # \x escapes are bytes in Go; a run of them is UTF-8 when it decodes as UTF-8
    try:
        return s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def go_literals(text: str) -> list:
    """(literal, offset) for every Go string literal."""
    out = []
    for m in _GO_TOKEN.finditer(text):
        if m.group(1) is not None:
            out.append((_go_unescape(m.group(1)), m.start()))
        elif m.group(2) is not None:
            out.append((m.group(2), m.start()))
    return out


# ── the tables' own expectations ─────────────────────────────────────────────
def _curl_expectations(raw: bytes) -> dict:
    """get_parts_list: host field of each part string, for an input expected OK."""
    text = raw.decode("utf-8", "surrogateescape")
    start = text.index("get_parts_list[]")
    block = text[start:text.index("};", start)].encode("utf-8", "surrogateescape")
    exp: dict = {}
    for entry in re.finditer(rb"\{(.*?)\},?\s*\n", block, re.S):
        lits = c_literals(entry.group(1))
        if len(lits) < 2 or b"CURLUE_OK" not in entry.group(1):
            continue
        parts = [p.strip() for p in lits[1].split("|")]
        if len(parts) >= 5 and not re.fullmatch(r"\[\d+\]", parts[4]):
            exp.setdefault(lits[0], set()).add("host:" + parts[4])
    return exp


def _go_url_expectations(text: str) -> dict:
    start = text.index("var urltests = []URLTest{")
    end = text.index("\n}\n", start)
    exp: dict = {}
    lits = [(v, o) for v, o in go_literals(text) if start <= o < end]
    for m in re.finditer(r"\n\t\{\n(.*?)\n\t\},", text[start:end], re.S):
        body = m.group(1)
        first = go_literals(body)
        if not first:
            continue
        h = re.search(r'Host:\s+("(?:[^"\\]|\\.)*"|`[^`]*`)', body)
        if h:
            host = go_literals(h.group(1))[0][0]
            exp.setdefault(first[0][0], set()).add("host:" + host)
    del lits
    return exp


def _go_mail_expectations(text: str) -> dict:
    start = text.index("func TestAddressParsing(")
    end = text.index("\n}\n", start)
    exp: dict = {}
    for m in re.finditer(r"\n\t\t\{\n?\s*(\"(?:[^\"\\]|\\.)*\"|`[^`]*`)(.*?)\n\t\t\},", text[start:end], re.S):
        src = go_literals(m.group(1))[0][0]
        for a in re.finditer(r'Address:\s+("(?:[^"\\]|\\.)*"|`[^`]*`)', m.group(2)):
            exp.setdefault(src, set()).add("mail:" + go_literals(a.group(1))[0][0])
    return exp


# ── IdnaTestV2 ───────────────────────────────────────────────────────────────
def _idna_unescape(s: str) -> str:
    s = re.sub(r"\\x\{([0-9A-Fa-f]+)\}", lambda m: chr(int(m.group(1), 16)), s)
    return re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), s)


def idna_rows(text: str) -> list:
    rows = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        f = [x.strip() for x in line.split(";")]
        source = _idna_unescape(f[0])
        to_unicode = _idna_unescape(f[1]) if f[1] else source
        u_status = f[2] if f[2] else "[]"
        ascii_n = _idna_unescape(f[3]) if f[3] else to_unicode
        n_status = f[4] if f[4] else u_status
        codes = set(re.findall(r"[A-Z]\d+(?:_\d+)?", n_status))
        rows.append({"source": source, "to_ascii_n": ascii_n, "status": sorted(codes)})
    return rows


def _idna_ok(row) -> bool:
    return not (set(row["status"]) - IGNORED_IDNA_CODES)


# ── extraction ───────────────────────────────────────────────────────────────
def extract(directory: Path) -> dict:
    """{vendored file name: bytes}."""
    vectors: dict = {}

    def add(src, v, expect=()):
        if not isinstance(v, str) or not v or len(v) > MAX_CHARS:
            return
        key = (src, v)
        vectors.setdefault(key, set()).update(expect)

    files = {}
    for s in _sources():
        raw = (directory / s["file"]).read_bytes()
        if _sha(raw) != s["sha256"]:
            raise SystemExit(f"{s['file']}: sha256 {_sha(raw)} is not {s['sha256']}")
        kind, sid = s["kind"], s["id"]
        if kind == "cpython":
            for v in python_literals(raw.decode("utf-8")):
                add(sid, v)
        elif kind == "curl":
            exp = _curl_expectations(raw)
            for v in c_literals(raw):
                if _keep(v):
                    add(sid, v, exp.get(v, ()))
        elif kind in ("go-url", "go-mail"):
            text = raw.decode("utf-8")
            exp = _go_url_expectations(text) if kind == "go-url" else _go_mail_expectations(text)
            for v, _ in go_literals(text):
                if _keep(v):
                    add(sid, v, exp.get(v, ()))
        elif kind == "idna":
            rows = idna_rows(raw.decode("utf-8"))
            for r in rows:
                ok = _idna_ok(r)
                add(sid + ":url", f"http://{r['source']}/",
                    ["host:" + r["to_ascii_n"]] if ok else [])
                add(sid + ":mail", f"user@{r['source']}",
                    ["mail:user@" + r["to_ascii_n"]] if ok else [])
            if s.get("pinned"):
                files[f"idna-{s['version']}.jsonl"] = _jsonl(rows)
        elif kind == "wpt-url":
            for e in json.loads(raw):
                if not isinstance(e, dict) or not isinstance(e.get("input"), str):
                    continue
                expect = []
                if (e.get("base") is None and not e.get("failure")
                        and e.get("protocol") in ("http:", "https:", "ws:", "wss:")):
                    expect = ["host:" + e["hostname"]]
                add(sid, e["input"], expect)
        elif kind == "wpt-toascii":
            for e in json.loads(raw):
                if isinstance(e, dict) and isinstance(e.get("input"), str):
                    add(sid, f"https://{e['input']}/x",
                        ["host:" + e["output"]] if isinstance(e.get("output"), str) else [])
        else:
            raise SystemExit(f"unknown kind {kind}")
    files["vectors.jsonl"] = _jsonl({"src": src, "v": v, "expect": sorted(exp)}
                                    for (src, v), exp in sorted(vectors.items()))
    return files


def _jsonl(rows) -> bytes:
    """UTF-8 JSON lines; a lone surrogate (an escape in a source no UTF-8 can
    hold) is written as its JSON ``\\u`` escape, so every line reads back as written."""
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in rows).encode("utf-8", "backslashreplace")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ("fetch", "extract", "verify"):
        print(__doc__)
        return 2
    cmd, directory = argv[0], Path(argv[1])
    if cmd == "fetch":
        return fetch(directory)
    files = extract(directory)
    manifest = json.loads(SOURCES.read_text(encoding="utf-8"))
    if cmd == "extract":
        for name, body in files.items():
            (OUT / name).write_bytes(body)
        manifest["extracted"] = {name: {"sha256": _sha(body), "lines": body.count(b"\n")}
                                 for name, body in sorted(files.items())}
        SOURCES.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
        for name, body in sorted(files.items()):
            n = body.count(b"\n")
            print(f"wrote {name}: {n} lines, sha256 {_sha(body)}")
        return 0
    bad = 0
    for name, body in sorted(files.items()):
        have = (OUT / name).read_bytes()
        want = manifest["extracted"][name]["sha256"]
        same = have == body and _sha(have) == want
        bad += not same
        print(f"{'ok' if same else 'DIFFERS'} {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
