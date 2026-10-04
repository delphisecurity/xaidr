"""Driver: A2 M3's detection deltas, through the INSTALLED sensor's tool-call path.

Run by tests/outside/harness.py with ``python -I`` inside a fresh venv. Every
spelling goes through ``Sensor.scan_tool_call("http_get", {"url": ...})``, the
seam an agent's URL fetch reaches, and the line printed per spelling is the
C-11 digest line (``action score category rules``).

``DECLARED`` is the enumerated delta list (ARCHITECTURE.md Q4, as measured at
M3): the spellings whose action M3 MOVES, each with the consumer that reaches
the address. Everything else here is a control that must not move.
``--compare BASE HEAD`` exits non-zero unless the moved set EQUALS the declared
set: no more, no fewer.

    python -I harness.py <base tree> <work> url_parse_deltas.py > base.json
    python -I harness.py <head tree> <work> url_parse_deltas.py > head.json
    python url_parse_deltas.py --compare base.json head.json
"""
import json
import sys

# spelling -> (moves at M3?, why)
SPELLINGS = {
    # newly link_local: a real consumer reaches 169.254.169.254
    "http://169．254．169．254/latest": (True, "fullwidth dots: httpx, ada"),
    "http://%31%36%39.254.169.254/latest": (True, "percent-encoded host: urllib3, ada"),
    "http://169.254.169.254\\latest": (True, "backslash after the host: ada, urllib3"),
    "http://169.254.169.254\\@corp.example/": (True, "the mirror: ada, urllib3"),
    "http:169.254.169.254/latest": (True, "R4, special scheme without //: ada"),
    "http:/169.254.169.254/latest": (True, "R4: ada"),
    "http://&a:foo(b]c@169.254.169.254/latest": (
        True, "urlsplit refuses it; httpx, urllib3 and ada send it"),
    # https: the SHELL_cloud_metadata_credentials regex accident does not see
    # these (no word boundary after `http`), so M3 moves the ACTION, not only
    # the rules. On http:// that regex already flagged most of the above.
    "https://169．254．169．254/latest": (True, "fullwidth dots over https: httpx, ada"),
    "https://169.254.169.254\\latest": (True, "backslash after the host, https: ada, urllib3"),
    "https://169.254.169.254\\@corp.example/": (True, "the mirror, https: ada, urllib3"),
    "https:169.254.169.254/latest": (True, "R4 over https: ada"),
    "https://&a:foo(b]c@169.254.169.254/latest": (
        True, "urlsplit refusal over https: httpx, urllib3, ada"),
    # added after the M3 milestone review, which found these moving undeclared
    "ws://169．254．169．254/": (True, "fullwidth dots over ws: httpx, ada"),
    "ftp://169．254．169．254/": (True, "fullwidth dots over ftp: httpx, ada"),
    "wss:169.254.169.254/": (True, "R4 over wss: ada"),
    "ftp:169.254.169.254/": (True, "R4 over ftp: ada"),
    "https:///169.254.169.254/latest": (True, "R4, three slashes: ada"),
    "https:\\\\169.254.169.254/latest": (True, "R4, backslashes: ada"),
    "https://169。254。169。254/": (True, "U+3002 dots: httpx IDNA, ada"),
    "https://169｡254｡169｡254/": (True, "U+FF61 dots: httpx IDNA, ada"),
    "https://%31%36%39.254.169.254/latest": (True, "percent-encoded over https: urllib3, ada"),
    "https://169.254.169.254%2e/": (True, "percent-encoded root dot: urllib3, ada"),
    "gopher://%31%36%39.254.169.254/": (
        True, "still flagged; rule net.scheme_smuggling -> net.metadata_link_local, 0.85 -> 0.90, execute -> credential_access"),
    "file://%31%36%39.254.169.254/x": (
        True, "still flagged; rule net.local_file_scheme -> net.metadata_link_local, 0.85 -> 0.90"),
    "http://0x_A9FEA9FE/": (True, "no longer an address (M3a digit check): no resolver reads `_`"),
    "http://0_251.254.169.254/": (True, "no longer an address (M3a digit check)"),
    # no longer link_local: no consumer reaches it
    "http://١٦٩.٢٥٤.١٦٩.٢٥٤/latest": (True, "Arabic-Indic digits: no consumer"),
    # controls: must not move
    "http://169.254.169.254/latest": (False, "control"),
    "https://169.254.169.254/latest": (False, "control"),
    "http://0xA9FEA9FE/": (False, "control: hex"),
    "http://2852039166/": (False, "control: decimal"),
    "http://0251.0376.0251.0376/": (False, "control: octal"),
    "http://[::ffff:169.254.169.254]/": (False, "control: mapped v6"),
    "http://１６９.２５４.１６９.２５４/latest": (
        False, "control: fullwidth DIGITS, caught before M3; coerce_ip alone drops it"),
    "http://corp.example\\@169.254.169.254/": (False, "control: urlsplit read it before M3"),
    "169.254.169.254/latest": (False, "control: scheme-less"),
    "169.254.169.254./latest": (False, "control: scheme-less root dot, no consumer reads it"),
    "0xA9FEA9FE/latest": (False, "control: scheme-less hex"),
    "https://0x.0x.0/": (False, "0.0.0.0 is private: classify-only, no action"),
    "http://1.2.3.256/": (False, "no longer an address (was public): no action either way"),
    "1.2.3.256/x": (False, "no longer a URL (was public): no action either way"),
    "http://10.0.0.5/x": (False, "control: private"),
    "http://127.1/": (False, "control: loopback"),
    "https://api.example.com/v1/orders": (False, "control: public name"),
    "http://metadata.google.internal/computeMetadata/v1/": (False, "control: metadata name"),
    "file:///etc/passwd": (False, "control: file scheme"),
    "gopher://10.0.0.1:6379/_": (False, "control: smuggling scheme"),
}


def _compare(base_path, head_path):
    base = json.load(open(base_path, encoding="utf-8"))
    head = json.load(open(head_path, encoding="utf-8"))
    print(f"base xaidr: {base['xaidr_file']} | py {base['python']}")
    print(f"head xaidr: {head['xaidr_file']} | py {head['python']}")
    modes_ok = head.get("modes_identical")
    print(f"head: OFF, RECORD and ENFORCE identical on every spelling: {modes_ok}"
          + ("" if modes_ok else f" {head.get('mode_diffs')}"))
    moved, declared = set(), {u for u, (m, _) in SPELLINGS.items() if m}
    for u, (_, why) in SPELLINGS.items():
        b, h = base["lines"][u], head["lines"][u]
        if b != h:
            moved.add(u)
        print(f"  {'MOVED' if b != h else 'same '}  {u!r:52} base={b}  head={h}   [{why}]")
    extra, missing = sorted(moved - declared), sorted(declared - moved)
    print(f"moved={len(moved)} declared={len(declared)} "
          f"undeclared_moves={extra} declared_but_unmoved={missing}")
    return 0 if not extra and not missing and modes_ok else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["--compare"]:
        sys.exit(_compare(sys.argv[2], sys.argv[3]))

    import sysconfig
    import warnings

    import xaidr

    site = sysconfig.get_paths()["purelib"]
    if not xaidr.__file__.startswith(site):
        sys.exit(f"REFUSING: xaidr imported from {xaidr.__file__}, not this venv's "
                 f"site-packages {site}; the source tree is shadowing the wheel")

    class _Null:
        def report(self, *a, **k):
            pass

        def close(self, *a, **k):
            pass

    import inspect

    def run(**kw):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sensor = xaidr.Sensor(agent_id="m3-deltas", reporter=_Null(), **kw)
        out = {}
        for url in SPELLINGS:
            r = sensor.scan_tool_call("http_get", {"url": url})
            rules = ",".join(sorted(r.rules or []))
            out[url] = f"{r.action} {float(r.score):.4f} {r.category or '-'} {rules or '-'}"
        return out

    lines = run()
    # C-11 on the spellings M3 moves: the delta must be the same in every
    # value-origin mode. A wheel without the parameter has no modes to compare.
    modes_identical, diffs = None, []
    if "value_origin" in inspect.signature(xaidr.Sensor).parameters:
        by_mode = {m: run(value_origin=m) for m in ("off", "record", "enforce")}
        diffs = [u for u in SPELLINGS
                 if len({by_mode[m][u] for m in by_mode} | {lines[u]}) != 1]
        modes_identical = not diffs
    print(json.dumps({"xaidr_file": xaidr.__file__, "python": sys.version.split()[0],
                      "lines": lines, "modes_identical": modes_identical,
                      "mode_diffs": diffs}, ensure_ascii=False))
