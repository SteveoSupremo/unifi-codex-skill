import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_mutation import FakeMutationClient
from mutationlib import (AmbiguousWriteError, ControllerIdentity, GuardedMutator,
                         StaleApprovalError, StateMismatch, ValidationError)
from unifi_common import WRITE_PHRASE

IDENTIFIER = '0123456789abcdef01234567'
IDENTITY = dict(controller_host='udm.test', site_id='site', internal_reference='default',
                site_name='Test', network_version='10.6.106')


class ForwardClient(FakeMutationClient):
    def __init__(self):
        super().__init__()
        self.port_forwards = [dict(_id=IDENTIFIER, site_id='legacy-site', name='HTTPS',
                                  enabled=True, proto='tcp', dst_port='443', fwd_port='443',
                                  fwd='192.168.6.25', pfwd_interface='all', log=False,
                                  src_limiting_enabled=False,
                                  destination_ips=[dict(interface='wan', destination_ip='any')]),
                              dict(_id='other', name='Keep', fwd='192.168.6.241', dst_port='8123')]
        self.networks = [dict(_id='servers', ip_subnet='192.168.6.1/24')]
        self.policies = [dict(id='generated', portForwardId=IDENTIFIER,
                              fwd='192.168.6.25', metadata=dict(origin='SYSTEM_DEFINED')),
                         dict(id='unrelated-policy', metadata=dict(origin='USER_DEFINED'))]
        self.forwarding_status = [dict(id='status', portForwardId=IDENTIFIER, fwd='192.168.6.25')]
        self.lose_response = False
        self.apply_write = True
        self.leave_policy_stale = False
        self.break_unrelated = False
        self.change_during_freshness = False
        self.collection_reads = 0
        self.status_delay_reads = 0
        self.pending_status = None

    def get(self, endpoint):
        if endpoint.endswith('/stat/portforward') and self.pending_status is not None:
            self.status_delay_reads -= 1
            if self.status_delay_reads <= 0:
                self.forwarding_status[0]['fwd'] = self.pending_status
                self.pending_status = None
        if endpoint.endswith('/rest/portforward'):
            self.collection_reads += 1
            if self.change_during_freshness and self.collection_reads == 3:
                self.port_forwards[0]['log'] = True
        return super().get(endpoint)

    def put(self, endpoint, body):
        self.calls.append(('PUT', endpoint, copy.deepcopy(body)))
        if self.apply_write:
            self.port_forwards[0] = copy.deepcopy(body)
            if not self.leave_policy_stale:
                self.policies[0]['fwd'] = body['fwd']
            if self.status_delay_reads:
                self.pending_status = body['fwd']
            else:
                self.forwarding_status[0]['fwd'] = body['fwd']
            if self.break_unrelated:
                self.port_forwards[1]['fwd'] = '192.168.6.99'
        if self.lose_response:
            raise TimeoutError('synthetic response loss')
        return [copy.deepcopy(body)]


class ForwardUpdateTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('mutationlib.time.sleep', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.client = ForwardClient()
        self.identity = ControllerIdentity(**IDENTITY)
        self.mutator = GuardedMutator(self.client, site_id='site', internal_site='default',
                                     controller_host='udm.test', site_name='Test', network_version='10.6.106',
                                     identity_reader=lambda: self.identity,
                                     snapshot_base=self.root/'snapshots', lock_path=self.root/'lock',
                                     journal_base=self.root/'operations',
                                     env={'UNIFI_ENABLE_WRITES': WRITE_PHRASE})

    def plan(self, address='192.168.6.16'):
        return self.mutator.port_forward_update(IDENTIFIER, address)['plan']

    def apply(self, token):
        return self.mutator.port_forward_update(IDENTIFIER, '192.168.6.16', dry_run=False, approval=token)

    def writes(self):
        return [c for c in self.client.calls if c[0] != 'GET']

    def test_plan_and_full_object_put_preserve_other_fields_and_records(self):
        original = copy.deepcopy(self.client.port_forwards)
        plan = self.plan()
        self.assertFalse(self.writes())
        proposed = copy.deepcopy(original[0]); proposed['fwd'] = '192.168.6.16'
        self.assertEqual(proposed, plan['proposed_state'])
        result = self.apply(plan['approval_token'])
        self.assertEqual('APPLIED', result['mode'])
        self.assertEqual(1, len(self.writes()))
        self.assertEqual(proposed, self.writes()[0][2])
        self.assertEqual(original[1], self.client.port_forwards[1])
        self.assertTrue(result['verification']['generated_policy_destination_matches'])

    def test_gate_requires_enablement_and_exact_token(self):
        token = self.plan()['approval_token']
        self.mutator.env['UNIFI_ENABLE_WRITES'] = 'disabled'
        with self.assertRaises(PermissionError): self.apply(token)
        self.mutator.env['UNIFI_ENABLE_WRITES'] = WRITE_PHRASE
        with self.assertRaises(PermissionError): self.apply('yes')
        self.assertFalse(self.writes())

    def test_changed_target_invalidates_token(self):
        token = self.plan()['approval_token']
        self.client.port_forwards[0]['log'] = True
        with self.assertRaises(PermissionError): self.apply(token)
        self.assertFalse(self.writes())

    def test_prewrite_concurrent_edit_is_refused(self):
        token = self.plan()['approval_token']
        self.client.change_during_freshness = True
        with self.assertRaises(StaleApprovalError): self.apply(token)
        self.assertFalse(self.writes())

    def test_identity_change_is_refused(self):
        token = self.plan()['approval_token']
        self.identity = ControllerIdentity(**{**IDENTITY, 'site_id': 'different'})
        with self.assertRaises(StaleApprovalError): self.apply(token)
        self.assertFalse(self.writes())

    def test_invalid_and_cross_subnet_addresses_are_refused(self):
        for address in ['invalid', '::1', '127.0.0.1', '224.0.0.1', '192.168.6.1',
                        '192.168.6.0', '192.168.6.255', '192.168.2.16']:
            with self.subTest(address=address), self.assertRaises(ValidationError): self.plan(address)
        self.assertFalse(self.writes())

    def test_unknown_version_or_schema_is_refused(self):
        self.mutator.identity = ControllerIdentity(**{**IDENTITY, 'network_version': 'future'})
        with self.assertRaises(ValidationError): self.plan()
        self.mutator.identity = ControllerIdentity(**IDENTITY)
        self.client.port_forwards[0]['metadata'] = dict(origin='SYSTEM_DEFINED')
        with self.assertRaises(ValidationError): self.plan()

    def test_expected_old_destination_guard(self):
        with self.assertRaises(StateMismatch):
            self.mutator.port_forward_update(IDENTIFIER, '192.168.6.16', expected={'fwd': '192.168.6.99'})
        self.assertFalse(self.writes())

    def test_identical_destination_is_noop(self):
        result = self.mutator.port_forward_update(IDENTIFIER, '192.168.6.25')
        self.assertEqual('NO_OP', result['mode'])
        self.assertFalse(self.writes())

    def test_lost_response_is_reconciled_without_retry(self):
        token = self.plan()['approval_token']; self.client.lose_response = True
        self.assertEqual('APPLIED', self.apply(token)['mode'])
        self.assertEqual(1, len(self.writes()))

    def test_delayed_status_is_reconciled_with_gets_only(self):
        token = self.plan()['approval_token']
        self.client.status_delay_reads = 3
        result = self.apply(token)
        self.assertEqual('APPLIED', result['mode'])
        self.assertEqual(3, result['verification']['reconciliation_attempts'])
        self.assertEqual(1, len(self.writes()))

    def test_absent_write_is_ambiguous_and_not_retried(self):
        token = self.plan()['approval_token']
        self.client.lose_response = True; self.client.apply_write = False
        with self.assertRaises(AmbiguousWriteError): self.apply(token)
        self.assertEqual(1, len(self.writes()))

    def test_stale_generated_policy_fails_verification(self):
        self.client.leave_policy_stale = True
        token = self.plan()['approval_token']
        with self.assertRaises(AmbiguousWriteError): self.apply(token)
        self.assertEqual(1, len(self.writes()))

    def test_unrelated_record_change_fails_verification(self):
        self.client.break_unrelated = True
        token = self.plan()['approval_token']
        with self.assertRaises(AmbiguousWriteError): self.apply(token)
        self.assertEqual(1, len(self.writes()))

    def test_rollback_has_separate_token_and_refuses_subsequent_edits(self):
        applied = self.apply(self.plan()['approval_token'])
        snapshot = Path(applied['plan']['snapshot_path'])
        revert = self.mutator.port_forward_revert(snapshot)['plan']
        self.assertNotEqual(applied['plan']['approval_token'], revert['approval_token'])
        self.mutator.port_forward_revert(snapshot, dry_run=False, approval=revert['approval_token'])
        self.assertEqual('192.168.6.25', self.client.port_forwards[0]['fwd'])
        with self.assertRaises(StateMismatch): self.mutator.port_forward_revert(snapshot)
