"""Synthetic regression tests; these do not replace a measured Windows lab run."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import collector
import forwarder
import sigma_rules


class AdminShareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(r for r in sigma_rules.load_rules()
                        if r['_source_file'] == 'suspicious_admin_share_access.yml')

    def matches(self, event_id=5140, share=r'\\*\ADMIN$', source='Security', **overrides):
        event = dict(event_id=event_id, source=source,
                     message=f'ShareName={share} | RelativeTargetName=tool.exe')
        event.update(overrides)
        return sigma_rules._rule_matches(self.rule, event)

    def test_admin_shares_on_both_event_ids(self):
        for event_id in (5140, 5145):
            for share in (r'\\*\ADMIN$', r'\\server\C$', r'\\server\admin$'):
                with self.subTest(event_id=event_id, share=share):
                    self.assertTrue(self.matches(event_id, share))

    def test_unrelated_events_and_shares_do_not_match(self):
        for event_id in (4624, 4625, 4688):
            self.assertFalse(self.matches(event_id))
        for share in (r'\\*\Documents', r'\\*\IPC$', r'\\*\ADMIN$backup', r'\\*\C$backup', ''):
            self.assertFalse(self.matches(share=share))
        self.assertFalse(self.matches(source='System'))
        self.assertFalse(self.matches(message='CommandLine=net use \\\\server\\ADMIN$'))
        self.assertFalse(self.matches(message=r'ShareName=\\*\Documents | RelativeTargetName=\ADMIN$'))
        self.assertFalse(self.matches(message=''))
        self.assertFalse(sigma_rules._rule_matches(self.rule, {}))

    def test_xml_forwarder_preserves_share_before_message_cap(self):
        for event_id in (5140, 5145):
            xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                   '<EventData><Data Name="ShareName">\\\\*\\C$</Data>'
                   '<Data Name="CommandLine">' + 'x' * 1000 + '</Data></EventData></Event>')
            event = {'Id': event_id, 'RecordId': 1, 'TimeCreated': '2026-10-22T12:00:00Z', 'Xml': xml}
            with patch.object(forwarder, '_run_powershell_json', return_value=[event]), \
                 patch.object(forwarder, 'send_event') as send:
                forwarder._poll_channel('Security', 'Security', '', 0)
            payload = send.call_args.args[0]
            self.assertLessEqual(len(payload['message']), 500)
            self.assertTrue(sigma_rules._rule_matches(self.rule, payload))
            self.assertEqual(payload['event_id'], event_id)

    def test_local_collector_preserves_share_with_localized_long_message(self):
        for event_id in (5140, 5145):
            event = SimpleNamespace(EventID=event_id, StringInserts=[
                'SID', 'analyst', 'DOMAIN', '0x123', 'File', '192.0.2.1', '1234', r'\\*\ADMIN$'])
            formatter = SimpleNamespace(SafeFormatMessage=lambda *_: 'x' * 1000)
            with patch.object(collector, 'win32evtlogutil', formatter, create=True):
                payload = collector._parse_event(event, 'Security')
            self.assertEqual(payload['user'], 'analyst')
            self.assertTrue(sigma_rules._rule_matches(self.rule, payload))
            self.assertLessEqual(len(payload['message']), 500)

    def test_public_evaluator_returns_alert(self):
        alert = sigma_rules.evaluate_sigma(dict(event_id=5145, source='Security',
                                               message=r'ShareName=\\*\C$'))
        self.assertEqual(alert['mitre_id'], 'T1570')
        self.assertEqual(alert['severity'], 'Medium')


if __name__ == '__main__':
    unittest.main()
