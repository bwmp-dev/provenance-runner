import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('updater', Path(__file__).with_name('updater.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class Signatures(unittest.TestCase):
    def test_ed25519_binds_every_release_field_and_operator_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(root/'key')], check=True, capture_output=True)
            public = subprocess.check_output(['openssl', 'pkey', '-in', str(root/'key'), '-pubout', '-outform', 'DER'])[-32:]
            release = {'version': 'git-example', 'url': 'https://assets.example/runner', 'sha256': 'a'*64, 'sizeBytes': 100, 'signature': ''}
            (root/'message').write_bytes(u.signing_bytes(release))
            subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(root/'key'), '-in', str(root/'message'), '-out', str(root/'sig')], check=True, capture_output=True)
            release['signature'] = base64.b64encode((root/'sig').read_bytes()).decode()
            key = base64.b64encode(public).decode()
            with patch.object(u, 'WORK', root):
                u.verify_release(release, key)
                for field, value in [('version', 'other'), ('url', 'https://evil.example/runner'), ('sha256', 'b'*64), ('sizeBytes', 101)]:
                    altered = dict(release, **{field: value})
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        u.verify_release(altered, key)
                with self.assertRaises(ValueError):
                    u.verify_release(release, base64.b64encode(bytes(32)).decode())

    def test_signed_input_refuses_injection_unknown_fields_and_oversize(self):
        base = {'version': 'v1', 'url': 'https://assets.example/runner', 'sha256': 'a'*64, 'sizeBytes': 100, 'signature': ''}
        for values in [{'version': 'v1\nurl:other'}, {'url': 'http://assets.example/runner'}, {'url': 'https://user:password@assets.example/runner'}, {'sizeBytes': True}, {'sizeBytes': u.MAX_BINARY+1}, {'shellCommand': 'anything'}]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                u.signing_bytes(dict(base, **values))


class Client:
    def __init__(self):
        self.requests = []
        self.response = {'phase': 'complete', 'outcome': 'succeeded'}
    def poll(self, operation='', report='idle'):
        self.requests.append((operation, report))
        return self.response


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root/'work'
        self.work.mkdir()
        self.patches = [patch.object(u, 'ROOT', self.root), patch.object(u, 'WORK', self.work), patch.object(u, 'protected')]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = Client()
        self.updater = u.Updater({}, self.client)
        self.op = {'id': '10000000-0000-0000-0000-000000000001', 'phase': 'committing', 'report': 'succeeded'}

    def test_ack_loss_after_admission_resumed_never_stops_runner(self):
        self.updater.save(self.op)
        with patch.object(u, 'service') as service:
            self.updater.step()
            service.assert_not_called()
        self.assertEqual(json.loads(self.updater.journal.read_text())['phase'], 'complete')
        self.assertEqual(self.client.requests, [(self.op['id'], 'succeeded')])

    def test_unreachable_backend_during_commit_preserves_worker(self):
        self.updater.save(self.op)
        with patch.object(self.client, 'poll', side_effect=OSError), patch.object(u, 'service') as service:
            with self.assertRaises(OSError):
                self.updater.step()
            service.assert_not_called()
        self.assertEqual(json.loads(self.updater.journal.read_text())['phase'], 'committing')

    def test_backend_terminal_truth_precedes_recovery_rollback(self):
        self.op['phase'] = 'verifying'
        self.updater.save(self.op)
        with patch.object(self.updater, 'rollback') as rollback:
            self.updater.step()
            rollback.assert_not_called()

    def test_incomplete_switch_rolls_back_only_after_platform_confirmation(self):
        self.op['phase'] = 'verifying'
        self.updater.save(self.op)
        self.client.response = {'phase': 'verify'}
        with patch.object(self.updater, 'rollback') as rollback:
            self.updater.step()
            rollback.assert_called_once()

    def test_pending_terminal_replay_restarts_retained_worker_without_switch(self):
        with patch.object(u, 'service') as service, patch.object(u, 'local_quiet', return_value=False), patch.object(self.updater, 'switch') as switch:
            self.updater.rollback(self.op)
            self.assertEqual([c.args for c in service.call_args_list], [('stop',), ('start',)])
            switch.assert_not_called()

    def test_corrupt_rollback_bytes_never_replace_runner(self):
        old = self.work/'old'
        old.write_bytes(b'corrupt')
        target = self.root/'runner'
        target.write_bytes(b'current')
        with self.assertRaises(ValueError):
            self.updater.switch(old, hashlib.sha256(b'expected').hexdigest())
        self.assertEqual(target.read_bytes(), b'current')

    def test_binary_switch_and_failed_health_restore_retained_bytes(self):
        for healthy, expected, report in [(True, b"new-binary", "succeeded"), (False, b"old-binary", "rolled_back")]:
            with self.subTest(healthy=healthy):
                if self.updater.journal.exists(): self.updater.journal.unlink()
                old = self.root/'runner'
                old.write_bytes(b"old-binary")
                old_hash = hashlib.sha256(old.read_bytes()).hexdigest()
                (self.root/'installed.json').write_text(json.dumps({'runnerSha256': old_hash}))
                release = {'sha256': hashlib.sha256(b"new-binary").hexdigest()}
                def poll(operation='', status='idle'):
                    if not operation: return {'phase': 'install', 'operationId': self.op['id'], 'release': release}
                    return {'phase': 'complete', 'outcome': status}
                self.client.poll = poll
                self.client.download = lambda release, path: path.write_bytes(b"new-binary")
                self.updater.config = {'releasePublicKey': 'fixture'}
                with patch.object(u, 'verify_release'), patch.object(u, 'local_quiet', return_value=True), patch.object(u, 'no_scopes'), patch.object(u, 'service'), patch.object(self.updater, 'healthy', side_effect=[healthy, True] if not healthy else [True]):
                    self.updater.step()
                self.assertEqual(old.read_bytes(), expected)
                journal = json.loads(self.updater.journal.read_text())
                self.assertEqual(journal['phase'], 'complete')
                self.assertEqual(journal['report'], report)
                self.assertEqual((self.work/(old_hash+'.elf')).read_bytes(), b"old-binary")

    def test_invalid_signed_release_reports_failure_without_stopping_worker(self):
        self.client.response = {'phase': 'install', 'operationId': self.op['id'], 'release': {}}
        self.updater.config = {'releasePublicKey': 'fixture'}
        with patch.object(u, 'verify_release', side_effect=ValueError), patch.object(u, 'service') as service:
            self.updater.step()
            service.assert_not_called()
        self.assertEqual(self.client.requests[-1], (self.op['id'], 'failed'))

    def test_local_replay_and_symlinks_fail_closed(self):
        state = self.root/'state'
        config = state/'config'
        config.mkdir(parents=True)
        journal = config/'.provenance-runner-journal.json'
        with patch.object(u, 'STATE', state):
            journal.write_text(json.dumps({'schemaVersion': 'provenance.runner-journal/v1alpha1', 'pendingMessage': 'AA=='}))
            self.assertFalse(u.local_quiet())
            journal.write_text(json.dumps({'schemaVersion': 'provenance.runner-journal/v1alpha1', 'pendingHeartbeat': 'AA=='}))
            self.assertTrue(u.local_quiet())  # Idle heartbeats are not terminal replay.
            journal.unlink()
            journal.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                u.local_quiet()




class ReleaseCredentialScope(unittest.TestCase):
    def test_client_keeps_redirects_disabled(self):
        with patch.object(u, 'read', return_value=('pru_'+'a'*64).encode()), patch.object(u.urllib.request, 'build_opener') as factory:
            u.Client({'credentialFile': '/operator/credential'})
        handler = factory.call_args.args[0]
        self.assertIsInstance(handler, u.NoRedirect)
        with self.assertRaises(ValueError):
            handler.redirect_request(None)

    def test_credentials_only_on_exact_assigned_api_path(self):
        payload = b'\x7fELF\x02\x01' + b'\x00'*12 + b'\x3e\x00'
        sha = hashlib.sha256(payload).hexdigest()
        expected = 'https://api.example/v1/runner-releases/'+sha
        for url in (expected, 'https://other.example/v1/runner-releases/'+sha, expected+'?x=1'):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmp:
                client = object.__new__(u.Client)
                client.config = {'apiOrigin':'https://api.example'}
                client.token = 'pru_'+'a'*64
                class Opener:
                    def open(self, request, timeout):
                        self.request = request
                        import io
                        return io.BytesIO(payload)
                client.opener = Opener()
                client.download({'url':url,'sha256':sha,'sizeBytes':len(payload)},Path(tmp)/'runner')
                self.assertEqual(client.opener.request.get_header('Authorization'), 'Bearer '+client.token if url==expected else None)
                self.assertEqual(client.opener.request.get_header('User-agent'), 'Provenance-Hosted-Updater/1.0 (https://provenance.bwmp.dev)')
                self.assertEqual(client.opener.request.full_url, url)
                self.assertEqual(client.opener.request.get_method(), 'GET')


    def test_poll_identifies_updater_and_preserves_request_authority(self):
        import io
        client = object.__new__(u.Client)
        client.config = {'apiOrigin': 'https://api.example', 'runnerId': '10000000-0000-0000-0000-000000000001'}
        client.token = 'pru_'+'a'*64
        response = {'operationId': '', 'phase': 'wait', 'release': None, 'previousVersion': '', 'healthy': False, 'outcome': ''}
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return io.BytesIO(json.dumps(response).encode())
        client.opener = Opener()
        self.assertEqual(client.poll(), response)
        request = client.opener.request
        self.assertEqual(request.full_url, client.config['apiOrigin']+'/v1/runner-updater/'+client.config['runnerId']+'/poll')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.get_header('User-agent'), 'Provenance-Hosted-Updater/1.0 (https://provenance.bwmp.dev)')
        self.assertEqual(request.get_header('Authorization'), 'Bearer '+client.token)
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertEqual(json.loads(request.data), {'operationId': '', 'report': 'idle'})
        self.assertEqual(client.opener.timeout, 30)


class MalformedCommands(unittest.TestCase):
    def test_actionable_command_requires_operation_identity(self):
        from unittest.mock import MagicMock
        client = object.__new__(u.Client)
        client.config = {'apiOrigin': 'https://api.example', 'runnerId': '10000000-0000-0000-0000-000000000001'}
        client.token = 'synthetic'
        client.opener = MagicMock()
        for phase in ['install', 'verify', 'complete']:
            client.opener.open.return_value.__enter__.return_value.read.return_value = json.dumps({'operationId':'', 'phase':phase, 'release':None, 'previousVersion':'', 'healthy':False, 'outcome':''}).encode()
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                client.poll()

    def test_malformed_release_reports_failure_before_any_service_change(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temp, patch.object(u, 'WORK', Path(temp)), patch.object(u, 'service') as service:
            client = MagicMock()
            client.poll.return_value = {'phase':'install','operationId':'10000000-0000-0000-0000-000000000001','release':None}
            updater = u.Updater({'releasePublicKey':'unused'}, client)
            updater.step()
            client.poll.assert_called_with('10000000-0000-0000-0000-000000000001', 'failed')
            service.assert_not_called()


if __name__ == '__main__':
    unittest.main()
