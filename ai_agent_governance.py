"""
🛡️ AI Agent Governance - Policy-Based Sandboxing Tutorial
Error-Safe Version (GitHub Ready)
"""

import os
import yaml
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import re

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


# ================= LOGGING =================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ================= CORE STRUCTURES =================

class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Action:
    name: str
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    policy_name: str
    is_terminal: bool = True


@dataclass
class AuditEntry:
    timestamp: datetime
    action: Action
    decision: Decision
    reason: str
    policy_matched: str


# ================= POLICY ENGINE =================

class PolicyRule:
    def __init__(self, name: str):
        self.name = name

    def evaluate(self, action: Action) -> Optional[PolicyResult]:
        raise NotImplementedError


class FilesystemPolicy(PolicyRule):
    def __init__(self, allowed_paths: List[str], denied_paths: List[str]):
        super().__init__("filesystem")
        self.allowed_paths = [os.path.abspath(p) for p in allowed_paths]
        self.denied_paths = [os.path.abspath(p) for p in denied_paths]

    def evaluate(self, action: Action):
        path = action.kwargs.get("path")
        if not path:
            return None

        path = os.path.abspath(path)

        for denied in self.denied_paths:
            if path.startswith(denied):
                return PolicyResult(Decision.DENY, f"{path} denied", self.name)

        for allowed in self.allowed_paths:
            if path.startswith(allowed):
                return PolicyResult(Decision.ALLOW, f"{path} allowed", self.name)

        return PolicyResult(Decision.DENY, f"{path} not allowed", self.name)


class NetworkPolicy(PolicyRule):
    def __init__(self, allowed_domains: List[str]):
        super().__init__("network")
        self.allowed_domains = allowed_domains

    def evaluate(self, action: Action):
        url = action.kwargs.get("url")
        if not url:
            return None

        match = re.search(r"https?://([^/]+)", url)
        domain = match.group(1) if match else url

        for allowed in self.allowed_domains:
            if domain.endswith(allowed):
                return PolicyResult(Decision.ALLOW, f"{domain} allowed", self.name)

        return PolicyResult(Decision.DENY, f"{domain} blocked", self.name)


class RateLimitPolicy(PolicyRule):
    def __init__(self, max_actions: int = 60):
        super().__init__("rate_limit")
        self.max_actions = max_actions
        self.history = []

    def evaluate(self, action: Action):
        now = datetime.utcnow()
        self.history = [t for t in self.history if now - t < timedelta(minutes=1)]

        if len(self.history) >= self.max_actions:
            return PolicyResult(Decision.DENY, "Rate limit exceeded", self.name)

        self.history.append(now)
        return None


class PolicyEngine:
    def __init__(self):
        self.rules = []
        self.audit_log = []

    def add_rule(self, rule: PolicyRule):
        self.rules.append(rule)

    def evaluate(self, action: Action):
        for rule in self.rules:
            result = rule.evaluate(action)
            if result:
                self._log(action, result)
                return result

        result = PolicyResult(Decision.ALLOW, "No rule blocked", "default")
        self._log(action, result)
        return result

    def _log(self, action, result):
        self.audit_log.append(
            AuditEntry(datetime.utcnow(), action, result.decision, result.reason, result.policy_name)
        )
        logger.info(f"{result.decision.value.upper()} - {action.name} - {result.reason}")


# ================= GOVERNED TOOL WRAPPER =================

class PolicyViolation(Exception):
    pass


def governed_tool(engine: PolicyEngine):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            action = Action(name=func.__name__, args=args, kwargs=kwargs)
            result = engine.evaluate(action)

            if result.decision == Decision.DENY:
                raise PolicyViolation(result.reason)

            print(f"✅ {result.reason}")
            return func(*args, **kwargs)

        return wrapper
    return decorator


# ================= TOOLS =================

def create_tools(engine: PolicyEngine):

    @governed_tool(engine)
    def read_file(path: str):
        with open(path, "r") as f:
            return f.read()

    @governed_tool(engine)
    def write_file(path: str, content: str):
        with open(path, "w") as f:
            f.write(content)
        return "File written"

    @governed_tool(engine)
    def web_request(url: str):
        return f"Simulated request to {url}"

    return {
        "read_file": read_file,
        "write_file": write_file,
        "web_request": web_request,
    }


# ================= OPTIONAL LLM AGENT =================

class GovernedAgent:
    def __init__(self, engine: PolicyEngine):
        self.engine = engine
        self.tools = create_tools(engine)

        if OpenAI and os.getenv("OPENAI_API_KEY"):
            self.client = OpenAI()
        else:
            self.client = None

    def run(self, user_request: str):
        if not self.client:
            return "LLM not available. Set OPENAI_API_KEY."

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": user_request}],
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"OpenAI Error: {e}"


# ================= MAIN =================

def main():
    print("🛡️ AI Agent Governance Demo\n")

    engine = PolicyEngine()
    engine.add_rule(FilesystemPolicy(["./workspace"], ["./etc"]))
    engine.add_rule(NetworkPolicy(["api.github.com"]))
    engine.add_rule(RateLimitPolicy())

    tools = create_tools(engine)

    os.makedirs("workspace", exist_ok=True)

    try:
        print(tools["write_file"]("workspace/test.txt", "Hello World"))
        print(tools["read_file"]("workspace/test.txt"))
        print(tools["web_request"]("https://api.github.com/users"))
    except PolicyViolation as e:
        print("❌", e)

    print("\nAudit Log:")
    for log in engine.audit_log:
        print(log.decision.value, "-", log.reason)

    print("\n✅ Demo complete")


if __name__ == "__main__":
    main()