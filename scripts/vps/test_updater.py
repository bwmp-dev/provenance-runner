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


INIT_SCOPE = b'init.scope loaded active running System and Service Manager\n'

def worker_scope_command(*args):
    if args == ('id', '-u', u.USER):
        return b'994\n'
    if args == ('runuser', '-u', u.USER, '--', 'env', 'XDG_RUNTIME_DIR=/run/user/994',
                'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/994/bus', 'systemctl', '--user',
                'list-units', '--type=scope', '--state=active,activating,deactivating', '--no-legend', '--plain'):
        return INIT_SCOPE
    raise AssertionError('Unexpected scope inspection command')


class ScopeInspection(unittest.TestCase):
    def test_empty_or_exact_user_manager_scope_allows_replacement(self):
        for output in (b'', INIT_SCOPE, b'  '+INIT_SCOPE+b'\n'):
            with self.subTest(output=output), patch.object(u, 'run', side_effect=[b'994\n', output]) as run:
                u.no_scopes()
                self.assertEqual(len(run.call_args_list), 2)
                for call in run.call_args_list:
                    worker_scope_command(*call.args)

    def test_any_other_scope_or_ambiguous_manager_row_refuses(self):
        for output in (
            INIT_SCOPE+b'provenance-test.scope loaded active running sandbox\n',
            b'other.scope loaded activating start unknown\n',
            b'init.scope-extra loaded active running manager\n',
            b'evil.scope loaded active running init.scope\n',
            b'init.scope', b'init.scope not-found active running manager\n',
            b'init.scope loaded deactivating stop manager\n', INIT_SCOPE+INIT_SCOPE,
        ):
            with self.subTest(output=output), patch.object(u, 'run', side_effect=[b'994\n', output]):
                with self.assertRaises(ValueError): u.no_scopes()

    def test_failed_command_and_invalid_worker_uid_fail_closed(self):
        for uid in (b'0\n', b'994\n995', b'../994', b'worker'):
            with self.subTest(uid=uid), patch.object(u, 'run', return_value=uid) as run:
                with self.assertRaises(ValueError): u.no_scopes()
                self.assertEqual(run.call_count, 1)
        with patch.object(u, 'run', side_effect=[b'994\n', OSError('inspection unavailable')]):
            with self.assertRaises(OSError): u.no_scopes()


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

    def test_catalog_signature_binds_canonical_payload_and_asset_pins(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(root/'key')], check=True, capture_output=True)
            public = subprocess.check_output(['openssl', 'pkey', '-in', str(root/'key'), '-pubout', '-outform', 'DER'])[-32:]
            digest = 'a'*64
            asset = {'uri':'https://api.example/v1/runner-catalog-assets/'+digest+'/paper.jar','sha256':digest,'filename':'paper.jar','sizeBytes':100}
            catalog = {'environmentId':'paper-1.21.8-60','paper':{'artifact':asset},'java':{'artifact':asset},
                       'probeVersion':'0.1.0','probeSourceCommit':'f'*40,'probe':asset,'preparedRuntime':{'artifact':asset}}
            payload = {'schemaVersion':'provenance.hosted-paper-catalog/v1','artifactHosts':['api.example'],'catalogs':[catalog]}
            canonical = json.dumps(payload,separators=(',',':'),sort_keys=True).encode()
            revision = dict(payload, sha256=hashlib.sha256(canonical).hexdigest(), signature='')
            (root/'message').write_bytes(u.catalog_signing_bytes(revision))
            subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(root/'key'),'-in',str(root/'message'),'-out',str(root/'sig')],check=True,capture_output=True)
            revision['signature'] = base64.b64encode((root/'sig').read_bytes()).decode()
            with patch.object(u,'WORK',root):
                u.verify_catalog(revision,base64.b64encode(public).decode())
                altered = json.loads(json.dumps(revision)); altered['catalogs'][0]['paper']['artifact']['sizeBytes'] = 101
                with self.assertRaises(ValueError): u.verify_catalog(altered,base64.b64encode(public).decode())
                altered = json.loads(json.dumps(revision)); altered['catalogs'][0]['paper']['artifact']['uri'] = 'https://evil.example/file'
                with self.assertRaises(ValueError): u.verify_catalog(altered,base64.b64encode(public).decode())

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
        with patch.object(u, 'service') as service, patch.object(u, 'run', side_effect=worker_scope_command), patch.object(u, 'local_quiet', return_value=False), patch.object(self.updater, 'switch') as switch:
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
                with patch.object(u, 'verify_release'), patch.object(u, 'local_quiet', return_value=True), patch.object(u, 'run', side_effect=worker_scope_command), patch.object(u, 'service'), patch.object(self.updater, 'healthy', side_effect=[healthy, True] if not healthy else [True]):
                    self.updater.step()
                self.assertEqual(old.read_bytes(), expected)
                journal = json.loads(self.updater.journal.read_text())
                self.assertEqual(journal['phase'], 'complete')
                self.assertEqual(journal['report'], report)
                self.assertEqual((self.work/(old_hash+'.elf')).read_bytes(), b"old-binary")

    def test_interrupted_install_recovers_with_real_manager_scope(self):
        old = b'old-binary'
        old_hash = hashlib.sha256(old).hexdigest()
        (self.work/(old_hash+'.elf')).write_bytes(old)
        (self.root/'runner').write_bytes(b'interrupted-new-binary')
        (self.root/'installed.json').write_text(json.dumps({'runnerSha256': 'interrupted'}))
        op = {'id': self.op['id'], 'phase': 'staged', 'oldSha256': old_hash}
        self.updater.save(op)
        def poll(operation='', report='idle'):
            if report == 'rolled_back': return {'phase': 'complete', 'outcome': 'rolled_back'}
            return {'phase': 'install'}
        self.client.poll = poll
        with patch.object(u, 'run', side_effect=worker_scope_command), patch.object(u, 'local_quiet', return_value=True), patch.object(u, 'service') as service, patch.object(self.updater, 'healthy', return_value=True):
            self.updater.step()
        self.assertEqual((self.root/'runner').read_bytes(), old)
        self.assertEqual([call.args for call in service.call_args_list], [('stop',), ('start',)])
        self.assertEqual(json.loads(self.updater.journal.read_text())['phase'], 'complete')
        self.assertEqual(json.loads(self.updater.journal.read_text())['report'], 'rolled_back')

    def test_scope_preflight_refuses_install_and_recovery_before_service_stop(self):
        busy = INIT_SCOPE+b'provenance-job.scope loaded active running sandbox\n'
        self.client.response = {'phase': 'install', 'operationId': self.op['id'], 'release': {}}
        self.updater.config = {'releasePublicKey': 'fixture'}
        with patch.object(u, 'verify_release'), patch.object(u, 'local_quiet', return_value=True), patch.object(u, 'run', side_effect=[b'994\n', busy]), patch.object(u, 'service') as service:
            self.updater.step()
            service.assert_not_called()
        self.assertFalse(self.updater.journal.exists())
        self.assertEqual(self.client.requests[-1], (self.op['id'], 'failed'))
        with patch.object(u, 'run', side_effect=[b'994\n', busy]), patch.object(u, 'service') as service, patch.object(self.updater, 'switch') as switch:
            with self.assertRaises(ValueError): self.updater.rollback(self.op)
            service.assert_not_called()
            switch.assert_not_called()

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

    def test_catalog_poll_and_assets_keep_credentials_on_exact_api_authority(self):
        import io
        client = object.__new__(u.Client)
        client.config = {'apiOrigin':'https://api.example','runnerId':'10000000-0000-0000-0000-000000000001'}
        client.token = 'pru_'+'a'*64
        response = {'operationId':'','phase':'wait','revision':None,'previousCatalogSha256':'','healthy':False,'outcome':''}
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return io.BytesIO(json.dumps(response).encode())
        client.opener = Opener()
        self.assertEqual(client.catalog_poll(), response)
        self.assertEqual(client.opener.request.full_url, client.config['apiOrigin']+'/v1/runner-catalogs/'+client.config['runnerId']+'/poll')
        payload = b'catalog asset'; digest = hashlib.sha256(payload).hexdigest()
        asset = {'uri':client.config['apiOrigin']+'/v1/runner-catalog-assets/'+digest+'/paper.jar','sha256':digest,'filename':'paper.jar','sizeBytes':len(payload)}
        class AssetOpener:
            def open(self, request, timeout): self.request=request; return io.BytesIO(payload)
        client.opener = AssetOpener()
        with tempfile.TemporaryDirectory() as temp:
            client.download_catalog_asset(asset, Path(temp)/'asset')
        self.assertEqual(client.opener.request.get_header('Authorization'), 'Bearer '+client.token)
        with self.assertRaises(ValueError):
            client.download_catalog_asset(dict(asset, uri='https://evil.example/v1/runner-catalog-assets/'+digest+'/paper.jar'), Path('/unused'))


class CatalogTransactions(unittest.TestCase):
    def test_environment_replaces_legacy_catalog_inputs_without_touching_runtime_policy(self):
        reconciler = u.CatalogReconciler({}, None)
        current = (b'PROVENANCE_CACHE_ROOT="/cache"\nPROVENANCE_PAPER_PROBE_URI="https://old"\n'
                   b'PROVENANCE_PAPER_PREPARED_RUNTIMES_JSON="[]"\n')
        catalogs = [{'environmentId':'paper-example'}]
        result = reconciler.catalog_environment(current, catalogs).decode()
        self.assertIn('PROVENANCE_CACHE_ROOT="/cache"\n', result)
        self.assertNotIn('PROVENANCE_PAPER_PROBE_URI', result)
        self.assertNotIn('PROVENANCE_PAPER_PREPARED_RUNTIMES_JSON', result)
        lines = dict(line.split('=',1) for line in result.splitlines())
        self.assertEqual(json.loads(json.loads(lines['PROVENANCE_PAPER_CATALOGS_JSON'])), catalogs)

    def test_restore_uses_root_private_backup_and_preserves_catalog_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root, work = Path(temp)/'root', Path(temp)/'work'
            root.mkdir(); work.mkdir()
            backup = work/'catalog-backup-operation'; backup.mkdir()
            originals = {'settings.json':b'{"old":true}\n','runner.env':b'OLD="yes"\n','installed.json':b'{"runnerSha256":"old"}'}
            for name,data in originals.items(): (backup/name).write_bytes(data)
            for name in originals: (root/name).write_bytes(b'new')
            reconciler = u.CatalogReconciler({},None)
            with patch.object(u,'ROOT',root), patch.object(u,'WORK',work), patch.object(u,'protected'), patch.object(u,'run',return_value=b'123\n'), patch.object(u.os,'chown'):
                reconciler.restore({'backup':'catalog-backup-operation'})
            for name,data in originals.items(): self.assertEqual((root/name).read_bytes(),data)

    def test_failed_health_rollback_restores_files_before_terminal_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root, work = Path(temp)/'root', Path(temp)/'work'
            root.mkdir(); work.mkdir()
            backup = work/'catalog-backup-operation'; backup.mkdir()
            originals = {'settings.json':b'{"old":true}\n','runner.env':b'OLD="yes"\n','installed.json':b'{"runnerSha256":"old"}'}
            for name,data in originals.items(): (backup/name).write_bytes(data)
            for name in originals: (root/name).write_bytes(b'new')
            class CatalogClient:
                def __init__(self): self.calls=[]
                def catalog_poll(self, operation='', report='idle'):
                    self.calls.append((operation,report)); return {'phase':'complete','outcome':report}
            client = CatalogClient(); reconciler = u.CatalogReconciler({},client)
            operation = {'id':'10000000-0000-0000-0000-000000000001','backup':'catalog-backup-operation','phase':'verifying','revision':{'sha256':'a'*64}}
            with patch.object(u,'ROOT',root), patch.object(u,'WORK',work), patch.object(u,'protected'), patch.object(u,'run',return_value=b'123\n'), patch.object(u.os,'chown'), patch.object(u,'no_scopes'), patch.object(u,'local_quiet',return_value=True), patch.object(u,'service') as service, patch.object(reconciler,'healthy',return_value=True):
                reconciler.journal = work/'catalog-operation.json'
                reconciler.rollback(operation)
            for name,data in originals.items(): self.assertEqual((root/name).read_bytes(),data)
            self.assertEqual([call.args for call in service.call_args_list],[('stop',),('start',)])
            self.assertEqual(client.calls,[(operation['id'],'rolled_back')])
            journal = json.loads(reconciler.journal.read_text())
            self.assertEqual((journal['phase'],journal['report']),('complete','rolled_back'))


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
