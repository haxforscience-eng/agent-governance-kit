"""Strict input validation and deterministic, fail-closed policy evaluation."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib
import json
import re
from urllib.parse import urlsplit

LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
EFFECTS = {"read", "write", "export", "admin"}
ENVIRONMENTS = {"sandbox", "staging", "production"}
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}\Z")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def exact_keys(value: dict, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - (optional or set()):
        raise ValueError("Missing or unexpected fields")


def identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid identifier")
    return value


def integer(value: object, minimum: int = 0, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Invalid bounded integer")
    return value


def strings(value: object, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 100 or any(not isinstance(x, str) for x in value):
        raise ValueError("Expected a nonempty string list")
    if len(set(value)) != len(value) or (allowed and not set(value) <= allowed):
        raise ValueError("Duplicate or unsupported list value")
    return value


def resource(value: str) -> str:
    if not isinstance(value, str) or len(value) > 300 or not re.fullmatch(r"[a-z][a-z0-9+.-]*://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*", value):
        raise ValueError("Resource must be a canonical, unescaped URI")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Resource traversal is not supported")
    return value


def hostname(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", value):
        raise ValueError("Expected an exact lowercase DNS hostname")
    return value


@dataclass(frozen=True)
class Intent:
    agent_id: str
    requester_id: str
    tool: str
    resource: str
    environment: str
    classification: str
    estimated_cost_cents: int
    destination: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Intent":
        fields = {"agent_id", "requester_id", "tool", "resource", "environment", "classification", "estimated_cost_cents"}
        exact_keys(data, fields, {"destination"})
        for name in ("agent_id", "requester_id", "tool"):
            identifier(data[name])
        resource(data["resource"])
        if data["environment"] not in ENVIRONMENTS or data["classification"] not in LEVELS:
            raise ValueError("Unsupported environment or classification")
        integer(data["estimated_cost_cents"])
        destination = data.get("destination")
        if destination is not None:
            if not isinstance(destination, str) or len(destination) > 500:
                raise ValueError("Invalid destination")
            u = urlsplit(destination)
            if u.scheme != "https" or not u.hostname or u.username or u.password or u.port not in (None, 443) or u.fragment or u.query:
                raise ValueError("Destination must be HTTPS without credentials, query or fragment")
            hostname(u.hostname)
            if u.netloc != u.hostname and u.netloc != u.hostname + ":443":
                raise ValueError("Destination hostname must be canonical")
        return cls(**data)

    def to_dict(self) -> dict:
        return asdict(self)


class Policy:
    """Loads administrator-owned policy. Inputs are not inferred from prompts."""
    def __init__(self, data: dict):
        exact_keys(data, {"version", "policy_id", "agents", "tools", "approvers", "approval_ttl_seconds", "max_cost_cents"})
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Unsupported policy version")
        identifier(data["policy_id"])
        integer(data["approval_ttl_seconds"], 1, 3600)
        integer(data["max_cost_cents"], 1)
        for name in ("agents", "tools", "approvers"):
            if not isinstance(data[name], dict) or not 1 <= len(data[name]) <= 100:
                raise ValueError("Policy registry must contain 1–100 entries")
            for key in data[name]:
                identifier(key)
        for spec in data["tools"].values():
            exact_keys(spec, {"effect"})
            if spec["effect"] not in EFFECTS:
                raise ValueError("Unknown tool effect")
        for grant in data["agents"].values():
            exact_keys(grant, {"tools", "resources", "environments", "max_classification", "egress_hosts"})
            strings(grant["tools"], set(data["tools"]))
            for item in strings(grant["resources"]):
                resource(item)
            strings(grant["environments"], ENVIRONMENTS)
            if grant["max_classification"] not in LEVELS:
                raise ValueError("Unknown classification ceiling")
            if not isinstance(grant["egress_hosts"], list) or len(grant["egress_hosts"]) > 100 or len(set(grant["egress_hosts"])) != len(grant["egress_hosts"]):
                raise ValueError("Invalid egress list")
            for host in grant["egress_hosts"]:
                hostname(host)
        for role in data["approvers"].values():
            if role not in {"risk", "owner"}:
                raise ValueError("Unknown approver role")
        self._encoded = canonical(data)
        self.fingerprint = hashlib.sha256(self._encoded).hexdigest()

    @property
    def data(self) -> dict:
        return json.loads(self._encoded)


@dataclass(frozen=True)
class Decision:
    outcome: str
    reasons: tuple[str, ...]
    required_roles: tuple[str, ...]
    policy_digest: str
    intent_digest: str

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(policy: Policy, intent: Intent, spent_cents: int = 0, stopped: bool = False) -> Decision:
    # Revalidate dataclasses: constructing Intent directly must not bypass validation.
    intent = Intent.from_dict(intent.to_dict())
    integer(spent_cents)
    if type(stopped) is not bool:
        raise ValueError("Invalid stop state")
    p = policy.data
    reasons: list[str] = []
    grant = p["agents"].get(intent.agent_id)
    tool = p["tools"].get(intent.tool)
    if stopped:
        reasons.append("EMERGENCY_STOP")
    if not grant:
        reasons.append("AGENT_NOT_REGISTERED")
    if not tool:
        reasons.append("TOOL_NOT_REGISTERED")
    if grant:
        if intent.tool not in grant["tools"]:
            reasons.append("TOOL_NOT_GRANTED")
        if not any(intent.resource == root or intent.resource.startswith(root + "/") for root in grant["resources"]):
            reasons.append("RESOURCE_OUT_OF_SCOPE")
        if intent.environment not in grant["environments"]:
            reasons.append("ENVIRONMENT_NOT_GRANTED")
        if LEVELS[intent.classification] > LEVELS[grant["max_classification"]]:
            reasons.append("CLASSIFICATION_EXCEEDS_GRANT")
        if intent.destination and urlsplit(intent.destination).hostname not in grant["egress_hosts"]:
            reasons.append("EGRESS_NOT_ALLOWED")
    if spent_cents + intent.estimated_cost_cents > p["max_cost_cents"]:
        reasons.append("BUDGET_EXCEEDED")
    if tool and tool["effect"] == "export" and not intent.destination:
        reasons.append("EXPORT_DESTINATION_REQUIRED")
    roles: tuple[str, ...] = ()
    if tool and not reasons:
        if intent.environment == "production" and tool["effect"] in {"write", "export", "admin"}:
            roles = ("owner", "risk")
        elif tool["effect"] in {"write", "export", "admin"} or LEVELS[intent.classification] >= LEVELS["confidential"]:
            roles = ("owner",)
    return Decision("deny" if reasons else "review" if roles else "allow", tuple(reasons or ["HUMAN_REVIEW_REQUIRED" if roles else "WITHIN_MANDATE"]), roles, policy.fingerprint, digest(intent.to_dict()))

