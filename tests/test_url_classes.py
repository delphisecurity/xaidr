"""URL carried in a tool argument: the metadata-endpoint bypass, and the
block/classify split the address measurement forces.

THE BUG THIS CLOSES. ``SHELL_cloud_metadata_credentials`` was the only URL rule
in the product, and it reached tool arguments by accident. Its alternation

    \\b(?:curl|wget|fetch|http|httpie|nc|ncat|python\\d?|node|ruby|perl)\\b …

was written to name the HTTPie binary ``http``. What satisfied it in
``http_get(url="http://169.254.169.254/…")`` was the literal SCHEME — ``http``
followed by ``:``, and ``:`` is a word boundary. The accident was one character
wide, because ``https`` has no word boundary after ``http``:

    http://169.254.169.254/latest/meta-data/     blocked 0.90
    https://169.254.169.254/latest/meta-data/    allowed 0.00

Measured across fifteen spellings of that ONE address, nine were allowed: https,
gopher, file, no-scheme, hex, decimal, octal, and the IPv6 unique-local form.

WHY THIS IS NOT A REPAIRED REGEX. Adding ``https`` to the alternation would have
kept the design that produced the bug — a list of spellings, where every form
nobody wrote down is a bypass. ``0xA9FEA9FE``, ``2852039166``,
``0251.0376.0251.0376`` and ``[::ffff:169.254.169.254]`` are all the same
destination, and a string list can only ever know the one someone typed. The rule
is now about the ADDRESS RANGE, decided by ``urlsplit`` + ``ipaddress``.

THE SPLIT UNDER TEST, and it is the whole design:

    link-local 169.254.0.0/16   BLOCKS. Every major cloud serves short-lived role
                                credentials there to whoever asks. 0 of 30
                                realistic benign agent URLs land in the range.

    non-http scheme             BLOCKS. file:// turns a fetcher into a local file
                                reader; gopher:// makes it speak an arbitrary line
                                protocol to an internal service. 0 of 30 benign.

    private / loopback          CLASSIFY ONLY, never blocks. 9 of 30 benign agent
                                URLs are private or loopback — in a service mesh
                                the private address IS the normal case. The
                                address cannot separate an internal service call
                                from a pivot, and the fact that would (configured
                                vs agent-generated) is not available at this seam.

    metadata HOSTNAMES          Stay a string list, deliberately. No parse can
                                tell that ``metadata.google.internal`` is a
                                metadata endpoint — that fact lives in DNS, and
                                resolving it would put a network call inside a
                                scanner, on attacker-controlled input.
"""

from __future__ import annotations

import io
import contextlib

import pytest

from xaidr.sensor import DelphiSensor
from xaidr.authz.classifier import classify, classify_url, extract_url
from xaidr.scanner.url_parse import parse_url


class _Null:
    def report(self, batch): pass
    def close(self): pass


@pytest.fixture(scope="module")
def sensor():
    return DelphiSensor(agent_id="url-classes", enforcement_mode="block", reporter=_Null())


def _scan(sensor, tool, args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return sensor.scan_tool_call(tool, args)


# ── the bypass: every spelling of one address ────────────────────────────────
# THE central table. Each of these is the SAME destination; nine of the fifteen
# were allowed before this change, and the two that were not blocked by design —
# they were blocked because the string `http:` happened to satisfy a binary-name
# alternation.

METADATA_FORMS = [
    ("http", "http://169.254.169.254/latest/meta-data/"),
    ("https", "https://169.254.169.254/latest/meta-data/"),
    ("gopher", "gopher://169.254.169.254/_latest"),
    ("no-scheme", "169.254.169.254/latest/meta-data/"),
    ("hex", "http://0xA9FEA9FE/latest/meta-data/"),
    ("decimal", "http://2852039166/latest/meta-data/"),
    ("octal", "http://0251.0376.0251.0376/latest/meta-data/"),
    ("ipv6-mapped", "http://[::ffff:169.254.169.254]/latest/"),
    ("userinfo-confusion", "http://evil.example.com@169.254.169.254/latest/"),
    ("port", "http://169.254.169.254:80/latest/meta-data/"),
    ("ecs-task-role", "http://169.254.170.2/v2/credentials/abc"),
    ("gce-hostname", "http://metadata.google.internal/computeMetadata/v1/token"),
    ("azure-hostname", "http://metadata.azure.com/metadata/instance"),
    ("alibaba", "http://100.100.100.200/latest/meta-data/"),
    ("aws-ipv6", "http://[fd00:ec2::254]/latest/meta-data/"),
]


@pytest.mark.parametrize(
    "name,url", METADATA_FORMS, ids=[f[0] for f in METADATA_FORMS]
)
def test_every_metadata_form_blocks(sensor, name, url):
    r = _scan(sensor, "http_get", {"url": url})
    assert r.action == "blocked", f"{name}: {url} -> {r.action}/{r.score} {r.rules}"


def test_the_scheme_is_not_what_decides(sensor):
    """The exact one-character bypass, pinned. http and https are the same fact."""
    http = _scan(sensor, "http_get", {"url": "http://169.254.169.254/latest/meta-data/"})
    https = _scan(sensor, "http_get", {"url": "https://169.254.169.254/latest/meta-data/"})
    assert http.action == https.action == "blocked"
    assert "net.metadata_link_local" in http.rules
    assert "net.metadata_link_local" in https.rules


# ── the gate is the VALUE, never the key ─────────────────────────────────────

@pytest.mark.parametrize(
    "key", ["url", "uri", "endpoint", "target", "href", "webhook", "callback",
            "src", "address", "wibble"],
)
def test_a_url_is_found_under_any_argument_key(sensor, key):
    """A key allowlist would be a gate the attacker chooses the combination to —
    the decision extract_sql already settled and documented."""
    r = _scan(sensor, "fetch", {key: "https://169.254.169.254/latest/meta-data/"})
    assert r.action == "blocked", f"key={key} -> {r.action} {r.rules}"


@pytest.mark.parametrize(
    "tool", ["http_get", "fetch_url", "webhook", "call_api", "anything"],
)
def test_a_url_is_found_regardless_of_tool_name(sensor, tool):
    r = _scan(sensor, tool, {"url": "https://169.254.169.254/latest/"})
    assert r.action == "blocked", f"tool={tool} -> {r.action} {r.rules}"


# ── non-http schemes ─────────────────────────────────────────────────────────

NON_HTTP = [
    ("file", "file:///etc/passwd", "net.local_file_scheme"),
    ("file-shadow", "file:///etc/shadow", "net.local_file_scheme"),
    ("gopher-redis", "gopher://10.0.0.5:6379/_FLUSHALL", "net.scheme_smuggling"),
    ("dict-memcached", "dict://127.0.0.1:11211/stats", "net.scheme_smuggling"),
    ("ldap", "ldap://10.1.2.3/", "net.scheme_smuggling"),
]


@pytest.mark.parametrize("name,url,rule", NON_HTTP, ids=[c[0] for c in NON_HTTP])
def test_non_http_schemes_block(sensor, name, url, rule):
    r = _scan(sensor, "http_get", {"url": url})
    assert r.action == "blocked", f"{name} -> {r.action}/{r.score}"
    assert rule in r.rules, f"{name} blocked via {r.rules}, expected {rule}"


# ── the false-positive half, which is what decides the design ────────────────
# 30 realistic agent URLs. NONE of these may block. Nine of them are private or
# loopback, and that is exactly why the private address does not enforce.

BENIGN_URLS = [
    "http://localhost:8000/health",
    "http://127.0.0.1:5432/",
    "http://10.2.14.7:8080/api/v1/orders",
    "http://payments.svc.cluster.local/v1/charge",
    "https://api.stripe.com/v1/charges",
    "http://192.168.1.20:3000/metrics",
    "https://hooks.slack.com/services/T0/B0/xxx",
    "http://prometheus.monitoring:9090/api/v1/query",
    "http://elasticsearch:9200/_cat/health",
    "https://raw.githubusercontent.com/o/r/main/README.md",
    "http://172.17.0.3:8080/ready",
    "http://minio.default.svc:9000/bucket/obj",
    "https://api.internal/health",
    "http://[::1]:8080/health",
    "http://0.0.0.0:8080/livez",
    "http://redis:6379/",
    "https://s3.us-east-1.amazonaws.com/bucket/key",
    "http://host.docker.internal:5000/api",
    "http://kubernetes.default.svc/api/v1/namespaces",
    "https://vault.corp.example.com:8200/v1/kv",
    "http://10.100.0.1:53/",
    "https://grafana.internal:3000/api/dashboards",
    "http://consul.service.consul:8500/v1/health",
    "https://registry.gitlab.com/v2/",
    "https://api.github.com/repos/org/repo",
    "http://jaeger-collector:14268/api/traces",
    "http://192.168.65.2:53/",
    "https://sentry.io/api/0/projects/",
    "http://mailhog:8025/api/v2/messages",
    "https://cdn.jsdelivr.net/npm/pkg@1/dist.js",
]


@pytest.mark.parametrize("url", BENIGN_URLS)
def test_benign_agent_urls_are_allowed(sensor, url):
    r = _scan(sensor, "http_get", {"url": url})
    assert r.action == "allowed", f"{url} -> {r.action}/{r.score} {r.rules}"


def test_the_benign_gate_in_aggregate(sensor):
    """One assertion carrying the FP number the design rests on."""
    bad = [
        (u, _scan(sensor, "http_get", {"url": u}).action)
        for u in BENIGN_URLS
        if _scan(sensor, "http_get", {"url": u}).action != "allowed"
    ]
    assert not bad, f"{len(bad)}/{len(BENIGN_URLS)} benign agent URLs not allowed: {bad}"


@pytest.mark.parametrize("url", [
    "http://10.2.14.7:8080/api/v1/orders",
    "http://192.168.1.20:3000/metrics",
    "http://172.17.0.3:8080/ready",
    "http://127.0.0.1:5432/",
    "http://[::1]:8080/health",
])
def test_private_and_loopback_classify_but_never_block(sensor, url):
    """CLASSIFY-ONLY, the terraform-destroy line. Measured 30% FP if it enforced,
    because in a service mesh the private address is the normal case."""
    assert _scan(sensor, "http_get", {"url": url}).action == "allowed"
    found = classify_url(url)
    assert found is not None, f"{url} produced no classification at all"
    assert found[0] == "read", found


def test_the_split_is_not_an_accident(sensor):
    """Link-local and private are neighbouring ranges with opposite verdicts. If a
    future edit collapses them, this is what fails."""
    assert _scan(sensor, "http_get", {"url": "http://169.254.169.254/x"}).action == "blocked"
    assert _scan(sensor, "http_get", {"url": "http://10.0.0.5/x"}).action == "allowed"


# ── the reader itself ────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", [
    "../config/settings.yaml",
    "/etc/hosts",
    "report.v2/summary",
    "example.txt/foo",
    "we saw traffic to http://169.254.169.254/latest/",   # prose, not a URL value
    "SELECT * FROM users WHERE id = 1",
    "Hello {{name}}",
    "1.2",
    "v1.2.3/build",
    "cat ~/.ssh/id_rsa",
    "",
    "   ",
])
def test_non_url_values_never_reach_the_url_reader(value):
    assert parse_url(value) is None, f"{value!r} was read as a URL: {parse_url(value)}"


def test_prose_quoting_a_metadata_url_is_not_extracted_as_a_url():
    """A sentence CONTAINING a URL is not a URL-valued argument. Prose belongs to
    the content path, where the L1 rules already read it."""
    assert extract_url({
        "body": "Postmortem: the actor fetched http://169.254.169.254/latest/ from the pod."
    }) is None


@pytest.mark.parametrize("url,kind", [
    ("http://169.254.169.254/", "link_local"),
    ("http://0xA9FEA9FE/x", "link_local"),
    ("http://2852039166/x", "link_local"),
    ("http://[::ffff:169.254.169.254]/", "link_local"),
    ("http://10.0.0.1/", "private"),
    ("http://127.0.0.1/", "loopback"),
    ("http://[::1]/", "loopback"),
    ("https://api.stripe.com/", None),          # a NAME cannot be classified
    ("http://metadata.google.internal/", None),  # ditto — hence the string list
])
def test_address_classification_across_literal_forms(url, kind):
    shape = parse_url(url)
    assert shape is not None, url
    assert shape.address == kind, f"{url} -> {shape.address}, expected {kind}"


def test_the_reader_is_bounded_and_never_raises():
    """Runs on attacker-controlled values: no input may raise, and the cap holds."""
    for value in ("http://" + "a" * 100_000, "http://[" * 5_000,
                  "://///", "http://:::::/", "\x00http://169.254.169.254/",
                  "http://" + "1." * 5_000):
        assert parse_url(value) is None or parse_url(value).raw  # no raise


def test_classification_can_raise_a_tool_that_reads_by_name():
    """`http_get` matches the read.* family by NAME, so without the override a
    metadata fetch would keep read/medium — the tool's usual purpose overriding
    what this call actually does. Only ever raises, never lowers."""
    assert classify("http_get", {"url": "https://api.stripe.com/v1/charges"}) == ("read", "medium")
    assert classify("http_get", {"url": "https://169.254.169.254/latest/"}) == (
        "credential_access", "critical"
    )


def test_hostname_metadata_is_a_string_list_on_purpose():
    """Pinned so nobody 'improves' it into a DNS lookup. Resolving a name here
    would put a network call inside a scanner, on attacker-controlled input, on
    the request path."""
    shape = parse_url("http://metadata.google.internal/computeMetadata/v1/")
    assert shape.address is None, "a name must not be resolved to an address"
    assert classify_url("http://metadata.google.internal/computeMetadata/v1/") == (
        "credential_access", "critical"
    )
