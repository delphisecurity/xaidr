"""DelphiSensor — main SDK entry point.

v0.2: Local L1/L2/DLP scanning by default. Brain only for L4 escalation
and telemetry. Matches npm sensor architecture.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time as _time
from typing import Optional
from uuid import uuid4

import httpx
import yaml
from agent_os.policies import PolicyDocument, PolicyEvaluator
from dotenv import load_dotenv

from .authz import classify, build_request, evaluate, parse_action_policy
from .reporters import Reporter
from .scanner.local import LocalScanner
from .telemetry import SyncTelemetryQueue
from .types import DelphiBlockedError, ScanResult

logger = logging.getLogger("xaidr.sensor")

DEFAULT_SENTINEL_URL = "https://xaidr.delphisecurity.ai"


class DelphiSensor:
    """Client for the Delphi Sentinel Brain.

    v0.2: Scans locally by default. Only escalates to Brain for
    ambiguous cases (L4 AprielGuard). Telemetry batched every 5s.

    Usage::

        async with Sensor(agent_id="my-agent") as sensor:
            result = sensor.scan("ignore previous instructions")
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        sentinel_url: str = DEFAULT_SENTINEL_URL,
        shadow_mode: bool = False,
        dlp_enabled: bool = True,
        block_threshold: float = 0.65,
        escalate_threshold: float = 0.20,
        telemetry_batch_size: int = 50,
        telemetry_flush_interval_sec: float = 5.0,
        reporter: "Reporter" = None,
    ):
        if not agent_id:
            raise ValueError("agent_id is required")

        load_dotenv()
        resolved_key = api_key or os.environ.get("DELPHI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "api_key not provided and DELPHI_API_KEY is not set in environment"
            )

        self.agent_id = agent_id
        self.sentinel_url = sentinel_url.rstrip("/")
        self._api_key = resolved_key
        self.shadow_mode = shadow_mode

        self._scanner = LocalScanner(
            api_key=resolved_key,
            sentinel_url=self.sentinel_url,
            block_threshold=block_threshold,
            escalate_threshold=escalate_threshold,
            shadow_mode=shadow_mode,
            dlp_enabled=dlp_enabled,
        )
        self._scanner_mode = "local"

        # Telemetry delivery is decoupled from any backend via the Reporter seam.
        # Default to StdoutReporter so the sensor emits events with no account
        # and no backend — NOT a Brain reporter.
        resolved_reporter = reporter
        if resolved_reporter is None:
            from .reporters import StdoutReporter
            resolved_reporter = StdoutReporter()
        self._telemetry = SyncTelemetryQueue(
            reporter=resolved_reporter,
            batch_size=telemetry_batch_size,
            flush_interval_sec=telemetry_flush_interval_sec,
        )
        self._closed = False

        self._quarantined = False
        self._quarantine_reason = None
        self._last_quarantine_check = 0.0
        self._quarantine_check_interval = 60.0

        self._policy_evaluator: Optional[PolicyEvaluator] = None
        self._policies_version: int = 0
        self._policy_yamls: list[str] = []

        self._blocked_tools: set[str] = set()
        self._blocked_urls: list[str] = []
        self._enforcement_mode: str = "blocking"

        self._action_policy: Optional[dict] = None
        self._trust_score: Optional[float] = None

        self._refresh_enforcement_status()

    def _refresh_enforcement_status(self) -> None:
        """Fetch quarantine status, blocked tools, blocked URLs from Brain.

        Called from __init__ and every ``_quarantine_check_interval`` seconds
        from scan(). Fail-open: if Brain is unreachable, retain last known
        enforcement state and continue.
        """
        try:
            resp = httpx.get(
                f"{self.sentinel_url}/v1/fleet/agent-config",
                params={"agentId": self.agent_id},
                headers={"x-delphi-api-key": self._api_key},
                timeout=5.0,
            )
            if resp.status_code != 200:
                return
            data = resp.json()

            if data.get("quarantined") or data.get("status") == "quarantined":
                if not self._quarantined:
                    print(f"[xaidr] QUARANTINED: {self.agent_id}")
                self._quarantined = True
                self._quarantine_reason = "Quarantined by fleet administrator"
            else:
                if self._quarantined:
                    print(f"[xaidr] Quarantine lifted for {self.agent_id}")
                self._quarantined = False
                self._quarantine_reason = None

            new_blocked_tools = set(data.get("blocked_tools") or [])
            if new_blocked_tools != self._blocked_tools:
                added = new_blocked_tools - self._blocked_tools
                removed = self._blocked_tools - new_blocked_tools
                if added:
                    print(f"[xaidr] Tools BLOCKED: {added}")
                if removed:
                    print(f"[xaidr] Tools UNBLOCKED: {removed}")
                self._blocked_tools = new_blocked_tools

            new_blocked_urls = data.get("blocked_urls") or []
            if new_blocked_urls != self._blocked_urls:
                print(f"[xaidr] Blocked URLs updated: {len(new_blocked_urls)} patterns")
                self._blocked_urls = new_blocked_urls

            new_mode = data.get("enforcement_mode") or "blocking"
            if new_mode != self._enforcement_mode:
                print(f"[xaidr] Enforcement mode: {self._enforcement_mode} -> {new_mode}")
                self._enforcement_mode = new_mode

            trust = data.get("trust_score")
            if trust is not None:
                try:
                    self._trust_score = float(trust)
                except (TypeError, ValueError):
                    pass

            # Action policy (versioned JSON, optional key). Absent or malformed
            # -> None, which the evaluator treats as monitor-only defaults.
            raw_action_policy = data.get("action_policy")
            new_action_policy = (
                parse_action_policy(raw_action_policy)
                if raw_action_policy is not None
                else None
            )
            if new_action_policy != self._action_policy:
                if new_action_policy is not None:
                    print(
                        f"[xaidr] Action policy updated: "
                        f"{len(new_action_policy['rules'])} rules, "
                        f"version {new_action_policy['version']}"
                    )
                else:
                    print("[xaidr] Action policy cleared (monitor-only defaults)")
                self._action_policy = new_action_policy

            new_policies_version = int(data.get("policies_version") or 0)
            new_policies = data.get("policies") or []

            if new_policies_version != self._policies_version:
                try:
                    if new_policies:
                        policy_docs = []
                        for p in new_policies:
                            yaml_str = p.get("yaml")
                            if not yaml_str:
                                continue
                            try:
                                policy_dict = yaml.safe_load(yaml_str)
                                policy_docs.append(PolicyDocument(**policy_dict))
                            except Exception as policy_exc:
                                logging.warning(
                                    f"[xaidr] failed to parse policy '{p.get('name', 'unknown')}': {policy_exc}"
                                )

                        if policy_docs:
                            self._policy_evaluator = PolicyEvaluator(policy_docs)
                            self._policy_yamls = [p.get("yaml") for p in new_policies if p.get("yaml")]
                            logging.info(
                                f"[xaidr] PolicyEvaluator rebuilt: "
                                f"{len(policy_docs)} policies, version {new_policies_version}"
                            )
                        else:
                            self._policy_evaluator = None
                            self._policy_yamls = []
                    else:
                        self._policy_evaluator = None
                        self._policy_yamls = []

                    self._policies_version = new_policies_version

                except Exception as exc:
                    logging.error(f"[xaidr] PolicyEvaluator rebuild failed: {exc}")
        except Exception:
            pass  # Fail-open: if Brain is unreachable, don't self-quarantine

    def _evaluate_policy(self, context: dict) -> tuple[bool, Optional[str]]:
        """Evaluate AGT policies against the given context.

        Returns (allowed, reason). If allowed is False, the action must be blocked.
        Fail-open: any exception returns (True, None) — never raise.
        """
        if self._policy_evaluator is None:
            return (True, None)
        try:
            decision = self._policy_evaluator.evaluate(context)
            if decision.allowed:
                return (True, None)
            else:
                return (False, decision.reason or "Blocked by AGT policy")
        except Exception as exc:
            logging.warning(f"[xaidr] policy evaluation error: {exc}")
            return (True, None)

    def _apply_mode(self, result: ScanResult) -> ScanResult:
        """In monitor/watch mode, downgrade a returned 'blocked' to 'flagged'.
        Telemetry keeps the true verdict; only the returned action is softened
        so the agent does not hard-block in monitor mode. Quarantine is never
        downgraded."""
        if self._enforcement_mode in ("monitor", "watch") and result.action == "blocked":
            return ScanResult(
                action="flagged",
                score=result.score,
                category=result.category,
                rules=result.rules,
                latency_ms=result.latency_ms,
            )
        return result

    def scan(
        self,
        prompt: str,
        direction: str = "input",
        destination: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> ScanResult:
        """Synchronous scan — used by LangChain middleware and direct calls.

        For agent→LLM (input/output) calls, ``destination``/``provider`` label
        the LLM endpoint (e.g. "anthropic") so the fleet graph can draw an
        agent→LLM edge. If neither is given, the edge falls back to a generic
        "llm" node.
        """
        now = _time.time()
        if now - self._last_quarantine_check > self._quarantine_check_interval:
            self._last_quarantine_check = now
            self._refresh_enforcement_status()

        if self._quarantined:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="quarantined",
                rules=["QUARANTINE_ENFORCED"],
                latency_ms=0,
            )
            self._telemetry.enqueue({
                "type": "scan",
                "agentId": self.agent_id,
                "data": {
                    "scanId": uuid4().hex[:12],
                    "agentId": self.agent_id,
                    "action": "blocked",
                    "score": 1.0,
                    "category": "quarantined",
                    "rules": ["QUARANTINE_ENFORCED"],
                    "direction": direction,
                    "destinationType": "external_api",
                    "destinationIdentifier": destination or provider or "llm",
                    "scanTimeMs": 0,
                    "promptLength": len(prompt),
                    "promptHash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
                    "prompt": prompt[:2000],
                },
            })
            return result

        result = self._scanner.scan(
            prompt=prompt,
            agent_id=self.agent_id,
            direction=direction,
        )

        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": result.action,
                "score": result.score,
                "category": result.category,
                "rules": result.rules,
                "direction": direction,
                "destinationType": "external_api",
                "destinationIdentifier": destination or provider or "llm",
                "scanTimeMs": result.latency_ms,
                "promptLength": len(prompt),
                "promptHash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
                "prompt": prompt[:2000],
            },
        })

        return self._apply_mode(result)

    def scan_output(
        self,
        response: str,
        destination: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> ScanResult:
        """Scan LLM output for DLP/secrets."""
        return self.scan(
            response, direction="output", destination=destination, provider=provider
        )

    def scan_a2a(self, message: str, destination: str) -> ScanResult:
        """Scan an A2A delegation message."""
        if self._quarantined:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="quarantined",
                rules=["QUARANTINE_ENFORCED"],
                latency_ms=0,
            )
            self._telemetry.enqueue({
                "type": "scan",
                "agentId": self.agent_id,
                "data": {
                    "scanId": uuid4().hex[:12],
                    "agentId": self.agent_id,
                    "action": "blocked",
                    "score": 1.0,
                    "category": "quarantined",
                    "rules": ["QUARANTINE_ENFORCED"],
                    "direction": "a2a",
                    "destinationAgent": destination,
                    "scanTimeMs": 0,
                    "promptLength": len(message),
                    "promptHash": hashlib.sha256(message.encode()).hexdigest()[:16],
                    "prompt": message[:2000],
                },
            })
            return result

        result = self._scanner.scan(
            prompt=message,
            agent_id=self.agent_id,
            direction="a2a",
        )
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": result.action,
                "score": result.score,
                "category": result.category,
                "rules": result.rules,
                "direction": "a2a",
                "destinationAgent": destination,
                "scanTimeMs": result.latency_ms,
                "promptLength": len(message),
                "promptHash": hashlib.sha256(message.encode()).hexdigest()[:16],
                "prompt": message[:2000],
            },
        })
        return self._apply_mode(result)

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: dict | None = None,
        mcp_server: Optional[str] = None,
    ) -> ScanResult:
        """Scan a tool call against blocked-tools list and per-agent policies.

        Use this for any non-LangChain integration (manual wrappers, custom
        frameworks). Enforces the same blocked_tools + AGT policy rules that
        protect_tools() applies, and emits telemetry so the dashboard records
        the verdict. Honors enforcement mode (monitor downgrades block->flag).

        Pass ``mcp_server`` to attribute the call to an MCP server (the fleet
        graph then draws an agent→MCP edge instead of a generic tool edge).
        """
        now = _time.time()
        if now - self._last_quarantine_check > self._quarantine_check_interval:
            self._last_quarantine_check = now
            self._refresh_enforcement_status()

        action = "allowed"
        score = 0.0
        category: Optional[str] = None
        rules: list[str] = []
        reason: Optional[str] = None

        # Action impact classification + local authz evaluation. Both never
        # raise; with no cached action_policy the decision is monitor-only.
        impact_class, impact_tier = classify(tool_name, arguments, mcp_server)
        authz = evaluate(
            self._action_policy,
            build_request(
                agent_id=self.agent_id,
                trust=self._trust_score,
                tool_name=tool_name,
                impact_class=impact_class,
                impact_tier=impact_tier,
                destination_type="mcp_server" if mcp_server else "tool_call",
                destination_identifier=mcp_server or tool_name,
                context={"mcp_server": mcp_server},
            ),
        )

        # Quarantine overrides everything
        if self._quarantined:
            action, score, category, rules = "blocked", 1.0, "quarantined", ["QUARANTINE_ENFORCED"]
        # Blocked-tools list
        elif tool_name in self._blocked_tools:
            action, score, category, rules = "blocked", 1.0, "blocked_tool", ["TOOL_BLOCKED"]
            reason = f"Tool '{tool_name}' blocked by fleet administrator"
        else:
            # Per-agent AGT policy evaluation
            allowed, policy_reason = self._evaluate_policy({"tool_name": tool_name})
            if not allowed:
                action, score, category, rules = "blocked", 1.0, "policy", ["POLICY_DENY"]
                reason = policy_reason
            elif authz.decision == "blocked":
                action, score, category, rules = "blocked", 1.0, "action_policy", ["ACTION_POLICY_BLOCK"]
                reason = authz.reason or f"Tool '{tool_name}' blocked by action policy"
                print(f"[xaidr] TOOL BLOCKED by action policy: {tool_name} ({authz.policy_id})")
            elif authz.decision == "approval_required":
                # Approval flows are not local; block and flag for approval.
                action, score, category, rules = "blocked", 1.0, "action_policy", ["ACTION_POLICY_APPROVAL_REQUIRED"]
                reason = authz.reason or f"Tool '{tool_name}' requires approval"
                print(f"[xaidr] TOOL requires approval: {tool_name} ({authz.policy_id})")

        result = ScanResult(
            action=action, score=score, category=category, rules=rules, latency_ms=0,
        )

        # Emit telemetry (mirrors the scan() enqueue shape, direction=tool_call)
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": action,
                "score": score,
                "category": category,
                "rules": rules,
                "direction": "tool_call",
                "toolName": tool_name,
                "destinationType": "mcp_server" if mcp_server else "tool_call",
                "destinationIdentifier": mcp_server or tool_name,
                "mcpServer": mcp_server,
                "impactClass": impact_class,
                "impactTier": impact_tier,
                "authzDecision": authz.decision,
                "authzPolicyId": authz.policy_id,
                "scanTimeMs": 0,
                "promptLength": 0,
                "promptHash": hashlib.sha256(tool_name.encode()).hexdigest()[:16],
            },
        })

        return self._apply_mode(result)

    def protect_tools(self, tools: list) -> list:
        """Wrap LangChain tools with blocking enforcement.

        Declares tool names to Brain (so the dashboard Tools tab shows
        them) and wraps each tool to short-circuit with a "blocked"
        message if its name is in ``self._blocked_tools``.

        Usage::

            protected = sensor.protect_tools([query_db, send_email])
            agent = create_agent(model=llm, tools=protected)

        Args:
            tools: List of LangChain ``@tool`` decorated functions.

        Returns:
            List of wrapped tools with blocking enforcement.
        """
        tool_names: list[str] = []
        for t in tools:
            name = getattr(t, "name", None) or getattr(t, "__name__", "unknown")
            tool_names.append(name)

        self._declare_tools(tool_names)

        wrapped = []
        for t in tools:
            tool_name = getattr(t, "name", None) or getattr(t, "__name__", "unknown")
            original_func = getattr(t, "func", None)

            def make_wrapper(orig_func, tname):
                def wrapper(*args, **kwargs):
                    def _emit(action, category, rule_list):
                        self._telemetry.enqueue({
                            "type": "scan",
                            "agentId": self.agent_id,
                            "data": {
                                "scanId": uuid4().hex[:12],
                                "agentId": self.agent_id,
                                "action": action,
                                "score": 1.0 if action == "blocked" else 0.0,
                                "category": category,
                                "rules": rule_list,
                                "direction": "tool_call",
                                "toolName": tname,
                                "scanTimeMs": 0,
                                "promptLength": 0,
                                "promptHash": hashlib.sha256(tname.encode()).hexdigest()[:16],
                            },
                        })
                    if tname in self._blocked_tools:
                        print(f"[xaidr] TOOL BLOCKED: {tname}")
                        _emit("blocked", "blocked_tool", ["TOOL_BLOCKED"])
                        return f"[BLOCKED] Tool '{tname}' has been blocked by the fleet administrator."
                    allowed, reason = self._evaluate_policy({"tool_name": tname})
                    if not allowed:
                        print(f"[xaidr] TOOL BLOCKED by policy: {tname} ({reason})")
                        _emit("blocked", "policy", ["POLICY_DENY"])
                        return f"[BLOCKED] Tool '{tname}' blocked by policy: {reason}"
                    _emit("allowed", None, [])
                    if orig_func is not None:
                        return orig_func(*args, **kwargs)
                    # Fallback: not a LangChain tool — call directly
                    return args[0] if args else None
                return wrapper

            new_func = make_wrapper(original_func, tool_name)

            # Preserve LangChain tool metadata (name, description, args_schema)
            # by copying the original tool with only `func` replaced. model_copy
            # is the supported Pydantic v2 path for LangChain BaseTool.
            if hasattr(t, "model_copy") and original_func is not None:
                new_tool = t.model_copy(update={"func": new_func})
            else:
                # Non-LangChain callable — wrap and return as-is
                new_func.__name__ = tool_name
                new_func.__doc__ = getattr(original_func, "__doc__", None) or f"Protected: {tool_name}"
                new_tool = new_func

            wrapped.append(new_tool)

        return wrapped

    def _declare_tools(self, tool_names: list[str]) -> None:
        """Register declared tools with Brain (best-effort)."""
        try:
            resp = httpx.post(
                f"{self.sentinel_url}/v1/fleet/declare-tools",
                json={"agentId": self.agent_id, "tools": tool_names},
                headers={"x-delphi-api-key": self._api_key},
                timeout=5.0,
            )
            if resp.status_code == 200:
                print(f"[xaidr] Declared {len(tool_names)} tools: {tool_names}")
        except Exception:
            pass  # Best-effort

    def protect_http(self, client: "httpx.Client") -> "ProtectedHttpClient":
        """Wrap an httpx.Client to auto-scan outgoing A2A HTTP calls.

        Every outgoing POST/PUT/PATCH request is scanned before sending.
        Message text is extracted from JSON body (message, prompt, content fields).
        Destination agent is inferred from URL (/agents/{id}/) or body (targetAgent, agentId).
        Response body is scanned for output DLP.

        Usage::

            import httpx
            from xaidr import Sensor

            sensor = Sensor(agent_id="orchestrator", ...)
            protected = sensor.protect_http(httpx.Client())

            # Every outgoing call is now scanned:
            resp = protected.post("http://billing:3002/ask", json={"message": task})

        Args:
            client: An httpx.Client instance to wrap.

        Returns:
            A ProtectedHttpClient that proxies all methods and scans POST/PUT/PATCH.
        """
        return ProtectedHttpClient(client, self)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._telemetry.close_sync()
        if hasattr(self._scanner, "close"):
            try:
                self._scanner.close()
            except Exception:
                pass

    async def __aenter__(self) -> "DelphiSensor":
        self._telemetry.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()


import re as _re


class ProtectedHttpClient:
    """Wraps httpx.Client to auto-scan outgoing A2A HTTP traffic.

    Proxies all methods to the underlying client. POST, PUT, and PATCH
    requests are scanned before sending. Response bodies are scanned
    for output DLP.
    """

    def __init__(self, client: "httpx.Client", sensor: DelphiSensor):
        self._client = client
        self._sensor = sensor

    def _extract_destination(self, url: str, json_body: dict | None) -> str:
        """Infer destination agent from URL pattern or body fields."""
        match = _re.search(r'/agents/([^/]+)', str(url))
        if match:
            return match.group(1)

        if json_body:
            for field in ('targetAgent', 'agentId', 'agent_id', 'destination'):
                val = json_body.get(field)
                if val and isinstance(val, str):
                    return val

        match = _re.search(r'://([^:./]+)', str(url))
        if match:
            host = match.group(1)
            if host not in ('localhost', '127', '0'):
                return host

        return 'unknown'

    # Known LLM API hosts → provider label. Used so agent→LLM edges in the
    # fleet graph are attributed to a named provider rather than a generic node.
    _PROVIDER_HOSTS = (
        ("anthropic", "anthropic"),
        ("openai", "openai"),
        ("azure", "azure-openai"),
        ("generativelanguage", "google"),
        ("googleapis", "google"),
        ("cohere", "cohere"),
        ("mistral", "mistral"),
        ("bedrock", "bedrock"),
        ("groq", "groq"),
    )

    def _extract_provider(self, url: str) -> Optional[str]:
        """Map a request URL host to a known LLM provider, or None."""
        match = _re.search(r'://([^/:]+)', str(url))
        host = match.group(1).lower() if match else str(url).lower()
        for needle, provider in self._PROVIDER_HOSTS:
            if needle in host:
                return provider
        return None

    def _extract_message(self, json_body: dict | None, content: str | bytes | None) -> str:
        """Extract the message text from request body."""
        if json_body:
            for field in ('message', 'prompt', 'content', 'input', 'text', 'query'):
                val = json_body.get(field)
                if val and isinstance(val, str):
                    return val

        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode('utf-8', errors='ignore')

        return ''

    def _extract_response_text(self, response: "httpx.Response") -> str:
        """Extract text from response body for output scanning."""
        try:
            data = response.json()
            if isinstance(data, dict):
                for field in ('response', 'message', 'content', 'output', 'text', 'result'):
                    val = data.get(field)
                    if val and isinstance(val, str):
                        return val
            return str(data)[:2000]
        except Exception:
            return ''

    def _scan_request(self, url: str, json_body: dict | None, content: str | bytes | None) -> None:
        """Scan outgoing request. Checks blocked URLs first, then A2A scan.

        Raises DelphiBlockedError if URL matches a blocked pattern or scan
        returns action=blocked.
        """
        url_str = str(url).lower()
        for blocked_url in self._sensor._blocked_urls:
            if blocked_url and blocked_url.lower() in url_str:
                result = ScanResult(
                    action="blocked",
                    score=1.0,
                    category="blocked_url",
                    rules=["URL_BLOCKED"],
                    latency_ms=0,
                )
                print(f"[xaidr] URL BLOCKED: {url} matches pattern '{blocked_url}'")
                raise DelphiBlockedError(result)

        allowed, reason = self._sensor._evaluate_policy({"url": str(url)})
        if not allowed:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="policy",
                rules=["POLICY_DENY"],
                latency_ms=0,
            )
            print(f"[xaidr] URL BLOCKED by policy: {url} ({reason})")
            raise DelphiBlockedError(result, message=f"URL '{url}' blocked by policy: {reason}")

        message = self._extract_message(json_body, content)
        if not message or len(message) < 3:
            return

        destination = self._extract_destination(url, json_body)

        result = self._sensor.scan_a2a(message, destination=destination)

        if result.action == 'blocked':
            raise DelphiBlockedError(result)

    def _scan_response(self, response: "httpx.Response") -> "httpx.Response":
        """Scan response body for output DLP.

        Labels the output scan with the LLM provider derived from the request
        host so the fleet graph draws an attributed agent→LLM edge.
        """
        text = self._extract_response_text(response)
        if text and len(text) >= 3:
            provider = self._extract_provider(str(response.url))
            result = self._sensor.scan(text, direction='output', provider=provider)
            if result.action == 'blocked':
                raise DelphiBlockedError(result)
        return response

    def post(self, url, *, json=None, content=None, headers=None, **kwargs):
        """POST with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.post(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def put(self, url, *, json=None, content=None, headers=None, **kwargs):
        """PUT with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.put(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def patch(self, url, *, json=None, content=None, headers=None, **kwargs):
        """PATCH with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.patch(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def get(self, url, **kwargs):
        """GET — passthrough, no scanning (read-only)."""
        return self._client.get(url, **kwargs)

    def delete(self, url, **kwargs):
        """DELETE — passthrough, no scanning."""
        return self._client.delete(url, **kwargs)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
