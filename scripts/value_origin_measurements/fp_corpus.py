"""Build a benign corpus of host-shaped tokens and URL hosts from files OUTSIDE
this project (system config, Homebrew package docs/configs/man pages, Python
package manifests), excluding test suites (adversarial by design) and
personal logs (they would put local IPs into a pushed PR)."""
import glob, gzip, json, os, re, sys
ROOTS = ["/etc", "/private/etc", "/opt/homebrew/etc", "/opt/homebrew/share/doc", "/opt/homebrew/share/man",
         "/usr/share/man", "/opt/homebrew/Cellar"]
SITE = sys.argv[2:]   # site-packages dirs to include (package manifests), e.g. $(python -c "import site;print(site.getsitepackages()[0])")
EXT = re.compile(r"\.(md|txt|rst|conf|cfg|ini|ya?ml|json|toml|[1-9]|gz|html?)$|/(README|NEWS|CHANGES|CHANGELOG|METADATA|hosts|services|protocols)[^/]*$", re.I)
SKIP = re.compile(r"/(tests?|testing|testdata|test_data|fixtures?)/|opena2a|value-origin|delphi|blank-canvas|xaidr", re.I)
URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://([^\s/?#\"'<>)\]]{1,253})")
QUAD = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
EMB = re.compile(r"\[?[0-9a-fA-F:]*:\d{1,3}(?:\.\d{1,3}){3}\]?")
BIG = re.compile(r"(?<![\w.])(?:0x[0-9a-fA-F]{9,16}|\d{10,20})(?![\w.])")
def files():
    seen = 0
    for root in ROOTS + SITE:
        for dp, dn, fn in os.walk(root):
            if SKIP.search(dp + "/"):
                dn[:] = []; continue
            for f in fn:
                p = os.path.join(dp, f)
                if SKIP.search(p) or not EXT.search(p):
                    continue
                try:
                    if os.path.getsize(p) > 2_000_000: continue
                    raw = gzip.open(p).read() if p.endswith(".gz") else open(p, "rb").read()
                    yield p, raw.decode("utf-8", "replace")
                    seen += 1
                except Exception:
                    continue
out = {"files": 0, "url_hosts": [], "tokens": []}
for p, text in files():
    out["files"] += 1
    for m in URL.finditer(text):
        host = m.group(1).rsplit("@", 1)[-1]
        out["url_hosts"].append((host, p))
    for rx, kind in ((QUAD, "quad"), (EMB, "embedded_v4"), (BIG, "big_number")):
        for m in rx.finditer(text):
            tok = m.group(0)
            if kind == "quad" and not any(len(x) > 1 and x[0] == "0" for x in tok.split(".")):
                continue                     # only the affected shape: a leading-zero part
            if kind == "embedded_v4":
                tail = tok.strip("[]").rsplit(":", 1)[-1].split(".")
                if not any(len(x) > 1 and x[0] == "0" for x in tail):
                    continue
            out["tokens"].append((tok, kind, p))
json.dump(out, open(sys.argv[1], "w"))
print(f"files read: {out['files']}; URL hosts: {len(out['url_hosts'])}; affected-shape tokens: {len(out['tokens'])}",
      {k: sum(1 for t in out['tokens'] if t[1] == k) for k in ('quad', 'embedded_v4', 'big_number')})
