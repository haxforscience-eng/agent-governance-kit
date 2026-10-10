import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from agent_governance import Intent, Policy, evaluate, GovernanceGate, ApprovalIssuer, GovernanceError
from agent_governance.cli import main, unique_pairs
from agent_governance.demo import run_demo

ROOT = Path(__file__).resolve().parents[1]


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.database = str(Path(self.folder.name) / 'governance.db')
        self.data = json.loads((ROOT / 'examples/policy.json').read_text())
        self.policy = Policy(self.data)
        self.now = 1_800_000_000
        self.approval_key, self.audit_key = b'a' * 32, b'b' * 32
        self.issuer = ApprovalIssuer(self.approval_key)
        self.gate = GovernanceGate(self.policy, self.database, self.approval_key, self.audit_key, lambda: self.now)
        self.addCleanup(self.gate.close)
        self.base = {'agent_id': 'cloud-advisor', 'requester_id': 'synthetic-operator', 'tool': 'inventory.read', 'resource': 'cloud://synthetic-account/compute/service-a', 'environment': 'sandbox', 'classification': 'internal', 'estimated_cost_cents': 10}

    def intent(self, **changes):
        return Intent.from_dict(self.base | changes)

    def request(self, **changes):
        return self.gate.submit(self.intent(**changes))

    def token(self, request, approver='business-owner', **changes):
        return self.issuer.issue(request, approver, changes.get('role', self.policy.data['approvers'][approver]), changes.get('now', self.now), changes.get('ttl', 300))

    def test_read_only_is_allowed_and_called_once(self):
        req = self.request()
        calls = []
        result = self.gate.execute(req['request_id'], lambda intent: calls.append(intent.tool))
        self.assertEqual(result['status'], 'completed')
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda intent: calls.append(intent.tool))
        self.assertEqual(calls, ['inventory.read'])
        self.assertTrue(self.gate.verify_audit(self.gate.evidence()['audit_head'])['valid'])

    def test_deny_rules_precede_review(self):
        cases = [({'agent_id': 'unknown'}, 'AGENT_NOT_REGISTERED'), ({'tool': 'shell.execute'}, 'TOOL_NOT_REGISTERED'), ({'resource': 'cloud://synthetic-account-evil'}, 'RESOURCE_OUT_OF_SCOPE'), ({'classification': 'restricted'}, 'CLASSIFICATION_EXCEEDS_GRANT'), ({'tool': 'evidence.export', 'destination': 'https://evidence.example.com.evil.test/path'}, 'EGRESS_NOT_ALLOWED'), ({'tool': 'evidence.export'}, 'EXPORT_DESTINATION_REQUIRED'), ({'estimated_cost_cents': 1001}, 'BUDGET_EXCEEDED')]
        for changes, reason in cases:
            with self.subTest(reason=reason):
                decision = evaluate(self.policy, self.intent(**changes))
                self.assertEqual(decision.outcome, 'deny')
                self.assertIn(reason, decision.reasons)
                calls = []
                req = self.gate.submit(self.intent(**changes))
                with self.assertRaises(GovernanceError):
                    self.gate.execute(req['request_id'], lambda i: calls.append(i))
                self.assertEqual(calls, [])

    def test_grant_environment_and_tool_boundary(self):
        for changes, expected in [({'agent_id': 'service-assistant', 'resource': 'tickets://synthetic-service', 'tool': 'cloud.change'}, 'TOOL_NOT_GRANTED'), ({'agent_id': 'service-assistant', 'resource': 'tickets://synthetic-service', 'environment': 'production'}, 'ENVIRONMENT_NOT_GRANTED')]:
            self.assertIn(expected, evaluate(self.policy, self.intent(**changes)).reasons)

    def test_threshold_equality_budget_and_classification(self):
        self.assertEqual(evaluate(self.policy, self.intent(estimated_cost_cents=1000)).outcome, 'allow')
        self.assertEqual(evaluate(self.policy, self.intent(classification='confidential')).outcome, 'review')
        self.assertEqual(evaluate(self.policy, self.intent(estimated_cost_cents=0), 1000).outcome, 'allow')

    def test_production_requires_two_independent_roles(self):
        req = self.request(tool='cloud.change', environment='production')
        self.assertEqual(req['decision']['required_roles'], ('owner', 'risk'))
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda i: None)
        self.gate.approve(self.token(req))
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda i: None)
        self.gate.approve(self.token(req, 'risk-officer'))
        self.assertEqual(self.gate.execute(req['request_id'], lambda i: 'synthetic')['status'], 'completed')

    def test_duplicate_approver_does_not_count_as_two_roles(self):
        req = self.request(tool='cloud.change', environment='production')
        self.gate.approve(self.token(req))
        with self.assertRaises(GovernanceError):
            self.gate.approve(self.token(req))
        with self.assertRaises(GovernanceError):
            self.gate.approve(self.token(req, role='risk'))

    def test_self_approval_refused(self):
        for requester in ['business-owner', 'risk-officer']:
            req = self.request(tool='cloud.change', environment='production', requester_id=requester)
            with self.assertRaises(GovernanceError):
                self.gate.approve(self.token(req, requester))

    def test_signature_binding_expiry_and_role_are_checked(self):
        req = self.request(tool='ticket.create')
        other = self.request(tool='ticket.create')
        bad = self.token(req)
        bad['claims']['request_id'] = other['request_id']
        expired = self.token(req, now=self.now - 300)
        wrong_digest_req = copy.deepcopy(req)
        wrong_digest_req['decision']['intent_digest'] = '0' * 64
        wrong_policy_req = copy.deepcopy(req)
        wrong_policy_req['decision']['policy_digest'] = '0' * 64
        tokens = [bad, expired, self.token(req, now=self.now + 1), self.token(req, ttl=301), self.token(req, role='risk'), self.token(wrong_digest_req), self.token(wrong_policy_req), {'claims': {}}, {'claims': {'request_id': []}}]
        for token in tokens:
            with self.subTest(token=token):
                with self.assertRaises(GovernanceError):
                    self.gate.approve(token)

    def test_expired_approval_at_execution_is_refused(self):
        req = self.request(tool='ticket.create')
        self.gate.approve(self.token(req))
        self.now += 300
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))

    def test_approval_storage_tampering_is_refused(self):
        req = self.request(tool='ticket.create')
        self.gate.approve(self.token(req))
        self.gate.db.execute("UPDATE approvals SET role='risk'")
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))

    def test_policy_change_invalidates_pending_work(self):
        req = self.request()
        revised = copy.deepcopy(self.data)
        revised['policy_id'] = 'new-version'
        self.gate.policy = Policy(revised)
        with self.assertRaisesRegex(GovernanceError, 'Policy changed'):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))

    def test_stored_intent_mutation_is_refused(self):
        req = self.request()
        mutated = self.base | {'resource': 'cloud://synthetic-account/other'}
        self.gate.db.execute('UPDATE requests SET intent=?', (json.dumps(mutated),))
        with self.assertRaisesRegex(GovernanceError, 'Stored intent changed'):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))

    def test_stop_blocks_previously_approved_work_and_can_be_released(self):
        req = self.request(tool='ticket.create')
        self.gate.approve(self.token(req))
        self.gate.set_emergency_stop(True, 'synthetic-operator')
        with self.assertRaisesRegex(GovernanceError, 'EMERGENCY_STOP'):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))
        self.gate.set_emergency_stop(False, 'synthetic-operator')
        self.assertEqual(self.gate.execute(req['request_id'], lambda i: None)['status'], 'completed')

    def test_budget_is_rechecked_at_reservation(self):
        first = self.request(estimated_cost_cents=800)
        second = self.request(estimated_cost_cents=300)
        self.gate.execute(first['request_id'], lambda i: None)
        with self.assertRaisesRegex(GovernanceError, 'BUDGET_EXCEEDED'):
            self.gate.execute(second['request_id'], lambda i: self.fail('called'))
        self.assertEqual(self.gate.evidence()['reserved_cost_cents'], 800)

    def test_failure_retains_reservation_without_logging_secret(self):
        req = self.request()
        def fail(_):
            raise RuntimeError('SECRET_SENTINEL')
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], fail)
        with self.assertRaises(GovernanceError):
            self.gate.execute(req['request_id'], lambda i: self.fail('retry'))
        evidence = self.gate.evidence()
        self.assertEqual(evidence['reserved_cost_cents'], 10)
        self.assertNotIn('SECRET_SENTINEL', json.dumps(evidence))

    def test_concurrent_reservation_executes_only_once(self):
        req = self.request()
        barrier = threading.Barrier(2)
        calls, outcomes = [], []
        def worker():
            gate = GovernanceGate(self.policy, self.database, self.approval_key, self.audit_key, lambda: self.now)
            try:
                barrier.wait(timeout=10)
                gate.execute(req['request_id'], lambda i: calls.append(i.tool))
                outcomes.append('completed')
            except GovernanceError:
                outcomes.append('blocked')
            finally:
                gate.close()
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(outcomes), ['blocked', 'completed'])
        self.assertEqual(calls, ['inventory.read'])
        self.assertEqual(self.gate.evidence()['reserved_cost_cents'], 10)

    def test_chain_tampering_and_tail_truncation_anchor(self):
        self.request()
        self.request()
        head = self.gate.evidence()['audit_head']
        self.assertTrue(self.gate.verify_audit(head)['valid'])
        self.gate.db.execute('DELETE FROM audit WHERE seq=2')
        self.assertTrue(self.gate.verify_audit()['valid'])
        self.assertFalse(self.gate.verify_audit(head)['valid'])
        self.gate.db.execute("UPDATE audit SET body='{}' WHERE seq=1")
        self.assertFalse(self.gate.verify_audit()['valid'])

    def test_bad_audit_prevents_execution(self):
        req = self.request()
        self.gate.db.execute("UPDATE audit SET mac=?", ('0' * 64,))
        with self.assertRaisesRegex(GovernanceError, 'Audit integrity'):
            self.gate.execute(req['request_id'], lambda i: self.fail('called'))

    def test_invalid_inputs_are_not_coerced(self):
        for changes in [{'estimated_cost_cents': True}, {'estimated_cost_cents': -1}, {'extra': 'unexpected'}, {'classification': 'secret'}, {'environment': 'prod'}, {'resource': 'cloud://synthetic-account/../other'}, {'resource': 'cloud://synthetic-account/%2e%2e'}, {'destination': 'http://evidence.example.com'}, {'destination': 'https://user@evidence.example.com'}, {'destination': 'https://evidence.example.com:444'}, {'destination': 'https://evidence.example.com/?secret=x'}, {'agent_id': 'agent\n'}]:
            with self.subTest(changes=changes):
                with self.assertRaises((ValueError, TypeError)):
                    Intent.from_dict(self.base | changes)
        with self.assertRaises(ValueError):
            evaluate(self.policy, Intent(**(self.base | {'estimated_cost_cents': True})))

    def test_policy_copy_cannot_mutate_live_policy(self):
        exposed = self.policy.data
        exposed['agents'].clear()
        self.data['agents'].clear()
        self.assertEqual(evaluate(self.policy, self.intent()).outcome, 'allow')

    def test_invalid_policy_and_keys(self):
        for change in [{'version': True}, {'version': 2}, {'approval_ttl_seconds': 0}, {'max_cost_cents': -1}, {'tools': {}}, {'agents': {}}, {'extra': 1}, {'approvers': {'bad': 'admin'}}]:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    Policy(self.data | change)
        with self.assertRaises(ValueError):
            ApprovalIssuer(b'short')
        with self.assertRaises(ValueError):
            GovernanceGate(self.policy, ':memory:', self.approval_key, self.approval_key)
        with self.assertRaises(ValueError):
            unique_pairs([('same', 1), ('same', 2)])

    def test_demo_has_actual_control_outcomes(self):
        data = run_demo(self.policy)
        self.assertEqual(data['summary'], {'scenarios': 9, 'completed': 3, 'blocked': 6})
        self.assertTrue(data['verification']['valid'])
        self.assertTrue(all(s['adapter_calls'] == (1 if s['execution']['status'] == 'completed' else 0) for s in data['scenarios']))

    def test_cli_evaluate_exit_codes_and_artifacts(self):
        intent_file = Path(self.folder.name) / 'intent.json'
        policy_file = ROOT / 'examples/policy.json'
        for changes, expected in [({}, 0), ({'tool': 'ticket.create'}, 2), ({'agent_id': 'unknown'}, 3), ({'extra': 'bad'}, 4)]:
            intent_file.write_text(json.dumps(self.base | changes))
            self.assertEqual(main(['evaluate', '--policy', str(policy_file), '--intent', str(intent_file)]), expected)
        output = Path(self.folder.name) / 'report'
        self.assertEqual(main(['demo', '--policy', str(policy_file), '--output', str(output)]), 0)
        self.assertTrue((output / 'executive-brief.md').exists())
        self.assertTrue(json.loads((output / 'evidence.json').read_text())['synthetic'])


if __name__ == '__main__':
    unittest.main()
