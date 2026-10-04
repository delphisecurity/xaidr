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
    moved, declared = set(), {u for u, (m, _) in SPELLINGS.items() if m}
    for u, (_, why) in SPELLINGS.items():
        b, h = base["lines"][u], head["lines"][u]
        if b != h:
            moved.add(u)
        print(f"  {'MOVED' if b != h else 'same '}  {u!r:52} base={b}  head={h}   [{why}]")
    extra, missing = sorted(moved - declared), sorted(declared - moved)
    print(f"moved={len(moved)} declared={len(declared)} "
          f"undeclared_moves={extra} declared_but_unmoved={missing}")
    return 0 if not extra and not missing else 1


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

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sensor = xaidr.Sensor(agent_id="m3-deltas", reporter=_Null())
    lines = {}
    for url in SPELLINGS:
        r = sensor.scan_tool_call("http_get", {"url": url})
        rules = ",".join(sorted(r.rules or []))
        lines[url] = f"{r.action} {float(r.score):.4f} {r.category or '-'} {rules or '-'}"
    print(json.dumps({"xaidr_file": xaidr.__file__, "python": sys.version.split()[0],
                      "lines": lines}, ensure_ascii=False))
