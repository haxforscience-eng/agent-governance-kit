"""Transactional reference gate, replay-resistant approvals, and HMAC audit chain."""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from typing import Callable
from .policy import Intent, Policy, canonical, digest, evaluate, exact_keys, identifier, integer


class GovernanceError(RuntimeError):
    pass


class ApprovalIssuer:
    """Trusted signer. Real identity authentication is an integration responsibility."""
    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Approval signing key needs at least 32 bytes")
        self._key = key

    def issue(self, request: dict, approver: str, role: str, now: int, ttl: int) -> dict:
        identifier(approver)
        integer(now, 0, 9_007_199_254_740_991)
        integer(ttl, 1, 3600)
        if role not in {"owner", "risk"}:
            raise ValueError("Unsupported approval role")
        claims = {"request_id": request["request_id"], "intent_digest": request["decision"]["intent_digest"], "policy_digest": request["decision"]["policy_digest"], "approver": approver, "role": role, "issued_at": now, "expires_at": now + ttl, "nonce": secrets.token_hex(16)}
        return {"claims": claims, "signature": hmac.new(self._key, canonical(claims), hashlib.sha256).hexdigest()}


class GovernanceGate:
    """A single-host, synchronous execution reference. Tool enforcement is mandatory."""
    def __init__(self, policy: Policy, database: str, approval_key: bytes, audit_key: bytes, clock: Callable[[], float] = time.time):
        ApprovalIssuer(approval_key)
        if not isinstance(audit_key, bytes) or len(audit_key) < 32 or hmac.compare_digest(approval_key, audit_key):
            raise ValueError("Use a distinct audit key with at least 32 bytes")
        self.policy, self.clock = policy, clock
        self._approval_key, self._audit_key = approval_key, audit_key
        self.db = sqlite3.connect(database, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), stopped INTEGER NOT NULL, spent INTEGER NOT NULL);
        INSERT OR IGNORE INTO runtime VALUES(1,0,0);
        CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, intent TEXT NOT NULL, intent_digest TEXT NOT NULL, policy_digest TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS approvals (nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL, approver TEXT NOT NULL, role TEXT NOT NULL, expires INTEGER NOT NULL, token TEXT NOT NULL, UNIQUE(request_id,approver));
        CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def _audit(self, event: str, details: dict):
        last = self.db.execute("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, previous = (last["seq"] + 1, last["mac"]) if last else (1, "0" * 64)
        body = {"sequence": seq, "timestamp": int(self.clock()), "event": event, "details": details}
        mac = hmac.new(self._audit_key, previous.encode() + canonical(body), hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO audit VALUES(?,?,?,?)", (seq, canonical(body).decode(), previous, mac))

    def submit(self, intent: Intent) -> dict:
        intent = Intent.from_dict(intent.to_dict())
        with self._transaction():
            state = self.db.execute("SELECT * FROM runtime WHERE id=1").fetchone()
            decision = evaluate(self.policy, intent, state["spent"], bool(state["stopped"]))
            request_id = secrets.token_hex(16)
            self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?)", (request_id, canonical(intent.to_dict()).decode(), decision.intent_digest, self.policy.fingerprint, "denied" if decision.outcome == "deny" else "pending"))
            self._audit("request_evaluated", {"request_id": request_id, "agent_id": intent.agent_id, "decision": decision.to_dict()})
        return {"request_id": request_id, "decision": decision.to_dict()}

    def _verify_token(self, token: dict, request: sqlite3.Row) -> dict:
        try:
            exact_keys(token, {"claims", "signature"})
            c = token["claims"]
            exact_keys(c, {"request_id", "intent_digest", "policy_digest", "approver", "role", "issued_at", "expires_at", "nonce"})
            for name in ("request_id", "approver", "nonce"):
                identifier(c[name])
            for name in ("intent_digest", "policy_digest"):
                if not isinstance(c[name], str) or len(c[name]) != 64:
                    raise ValueError("Invalid digest")
            integer(c["issued_at"], 0, 9_007_199_254_740_991)
            integer(c["expires_at"], 0, 9_007_199_254_740_991)
            signature = hmac.new(self._approval_key, canonical(c), hashlib.sha256).hexdigest()
            if not isinstance(token["signature"], str) or not hmac.compare_digest(token["signature"], signature):
                raise ValueError("Invalid signature")
            now = int(self.clock())
            intent = Intent.from_dict(json.loads(request["intent"]))
            p = self.policy.data
            if c["request_id"] != request["id"] or c["intent_digest"] != digest(intent.to_dict()) or c["policy_digest"] != self.policy.fingerprint or c["policy_digest"] != request["policy_digest"]:
                raise ValueError("Approval binding mismatch")
            if c["issued_at"] > now or c["expires_at"] <= now or not 0 < c["expires_at"] - c["issued_at"] <= p["approval_ttl_seconds"]:
                raise ValueError("Approval expired or exceeds lifetime")
            if p["approvers"].get(c["approver"]) != c["role"] or c["approver"] == intent.requester_id or c["approver"] == intent.agent_id:
                raise ValueError("Approver identity or separation of duties invalid")
            return c
        except (ValueError, TypeError, KeyError) as exc:
            raise GovernanceError(str(exc)) from exc

    def approve(self, token: dict) -> None:
        try:
            self._approve(token)
        except GovernanceError as exc:
            with self._transaction():
                self._audit("approval_refused", {"reason": str(exc)[:200]})
            raise

    def _approve(self, token: dict) -> None:
        with self._transaction():
            try:
                request_id = token["claims"]["request_id"]
            except (KeyError, TypeError) as exc:
                raise GovernanceError("Invalid approval envelope") from exc
            if not isinstance(request_id, str):
                raise GovernanceError("Invalid request ID")
            request = self.db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if not request or request["status"] != "pending":
                raise GovernanceError("Request is not pending")
            claims = self._verify_token(token, request)
            decision = evaluate(self.policy, Intent.from_dict(json.loads(request["intent"])))
            if claims["role"] not in decision.required_roles:
                raise GovernanceError("Approval role is not required")
            try:
                self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?)", (claims["nonce"], request_id, claims["approver"], claims["role"], claims["expires_at"], canonical(token).decode()))
            except sqlite3.IntegrityError as exc:
                raise GovernanceError("Duplicate approval or replay") from exc
            self._audit("approval_recorded", {"request_id": request_id, "approver": claims["approver"], "role": claims["role"], "expires_at": claims["expires_at"]})

    def set_emergency_stop(self, stopped: bool, operator: str):
        if type(stopped) is not bool:
            raise ValueError("Expected boolean stop state")
        identifier(operator)
        with self._transaction():
            self.db.execute("UPDATE runtime SET stopped=? WHERE id=1", (int(stopped),))
            self._audit("emergency_stop_changed", {"stopped": stopped, "operator": operator})

    def execute(self, request_id: str, executor: Callable[[Intent], object]) -> dict:
        try:
            return self._execute(request_id, executor)
        except GovernanceError as exc:
            with self._transaction():
                self._audit("execution_refused", {"request_id": request_id, "reason": str(exc)[:200]})
            raise

    def _execute(self, request_id: str, executor: Callable[[Intent], object]) -> dict:
        identifier(request_id)
        with self._transaction():
            request = self.db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if not request or request["status"] != "pending":
                raise GovernanceError("Request is not pending; replay is refused")
            if request["policy_digest"] != self.policy.fingerprint:
                raise GovernanceError("Policy changed; submit a new request")
            state = self.db.execute("SELECT * FROM runtime WHERE id=1").fetchone()
            intent = Intent.from_dict(json.loads(request["intent"]))
            if digest(intent.to_dict()) != request["intent_digest"]:
                raise GovernanceError("Stored intent changed; submit a new request")
            if not self.verify_audit()["valid"]:
                raise GovernanceError("Audit integrity check failed")
            decision = evaluate(self.policy, intent, state["spent"], bool(state["stopped"]))
            if decision.outcome == "deny":
                raise GovernanceError(",".join(decision.reasons))
            approvals = self.db.execute("SELECT * FROM approvals WHERE request_id=?", (request_id,)).fetchall()
            roles = set()
            for approval in approvals:
                try:
                    claims = self._verify_token(json.loads(approval["token"]), request)
                    if approval["approver"] != claims["approver"] or approval["role"] != claims["role"] or approval["expires"] != claims["expires_at"] or approval["nonce"] != claims["nonce"]:
                        raise GovernanceError("Approval storage mismatch")
                    roles.add(claims["role"])
                except GovernanceError:
                    continue
            if not set(decision.required_roles) <= roles:
                raise GovernanceError("Missing valid independent approval roles")
            self.db.execute("UPDATE requests SET status='executing' WHERE id=?", (request_id,))
            self.db.execute("UPDATE runtime SET spent=spent+? WHERE id=1", (intent.estimated_cost_cents,))
            self._audit("execution_reserved", {"request_id": request_id, "intent_digest": decision.intent_digest, "policy_digest": decision.policy_digest, "reserved_cost_cents": intent.estimated_cost_cents})
        # Reservation commits before the callback. A crash never replays a side effect.
        try:
            result = executor(intent)
        except Exception as exc:
            with self._transaction():
                self.db.execute("UPDATE requests SET status='failed' WHERE id=?", (request_id,))
                self._audit("execution_failed", {"request_id": request_id, "error_type": type(exc).__name__})
            raise GovernanceError("Executor failed; reservation retained, automatic retry refused") from exc
        with self._transaction():
            self.db.execute("UPDATE requests SET status='completed' WHERE id=?", (request_id,))
            self._audit("execution_completed", {"request_id": request_id})
        return {"request_id": request_id, "status": "completed", "result": result}

    def evidence(self) -> dict:
        entries = [{"body": json.loads(r["body"]), "previous": r["previous"], "mac": r["mac"]} for r in self.db.execute("SELECT * FROM audit ORDER BY seq")]
        state = self.db.execute("SELECT stopped,spent FROM runtime WHERE id=1").fetchone()
        return {"policy_digest": self.policy.fingerprint, "audit_head": entries[-1]["mac"] if entries else "0" * 64, "entries": entries, "reserved_cost_cents": state["spent"], "emergency_stop": bool(state["stopped"])}

    def verify_audit(self, expected_head: str | None = None) -> dict:
        previous = "0" * 64
        for sequence, row in enumerate(self.db.execute("SELECT * FROM audit ORDER BY seq"), 1):
            try:
                body = json.loads(row["body"])
                mac = hmac.new(self._audit_key, previous.encode() + canonical(body), hashlib.sha256).hexdigest()
                if row["seq"] != sequence or body["sequence"] != sequence or row["previous"] != previous or not hmac.compare_digest(row["mac"], mac):
                    return {"valid": False, "first_invalid_sequence": sequence, "externally_anchored": expected_head is not None}
                previous = row["mac"]
            except (ValueError, KeyError, TypeError):
                return {"valid": False, "first_invalid_sequence": sequence, "externally_anchored": expected_head is not None}
        return {"valid": expected_head is None or hmac.compare_digest(previous, expected_head), "audit_head": previous, "externally_anchored": expected_head is not None}
