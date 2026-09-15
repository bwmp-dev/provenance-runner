import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('measured_network_acceptance', Path(__file__).parent/'network-policy/measured_acceptance.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class MeasuredAcceptanceTests(unittest.TestCase):
    def test_protected_failure_evidence_is_not_chmodded(self):
        with mock.patch.object(driver.tempfile, 'mkdtemp', return_value='/tmp/owned-fixture') as create, mock.patch.object(driver.shutil, 'rmtree') as remove:
            with self.assertRaisesRegex(RuntimeError, 'original refusal'):
                with driver.fixture_workspace() as path:
                    self.assertEqual(path, '/tmp/owned-fixture')
                    raise RuntimeError('original refusal')
            create.assert_called_once_with(prefix='provenance-measured-route-', dir='/var/tmp')
            remove.assert_called_once_with('/tmp/owned-fixture', ignore_errors=True)

    def test_all_repeated_real_cases_and_cleanup_are_mandatory(self):
        rows = ['--- PASS: TestMeasuredAuthorityRouteSentry'+case+' (1s)' for case in ('Withdrawal', 'Expiry', 'ChildMismatch', 'OwnedLaunch', 'OwnedNormal', 'OwnedGatedStartup', 'JournalRefusal', 'BundleRefusal', 'PreparedRefusal', 'LinkRefusal', 'LayoutRefusal', 'UplinkRefusal') for _ in range(3)]
        rows += ['{"measuredRoutedOwnedLoopDetached": true}']
        rows += ['{"exclusiveMeasuredJobScopesRemoved": true}']
        rows += ['{"measuredJobJournalRetired": true}']
        rows += ['{"measuredBundleJournalRetired": true}']
        rows += ['{"measuredHostUplinkJournalRetired": true}']
        rows += ['--- PASS: TestMeasuredHostUplinkColdRecovery (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredControlListener (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredNetworkSessionRouterLoss/root-observation-transfer (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperServiceKernel (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperServiceWithdrawalKernel (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperServiceReleaseRefusalKernel (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperServiceEventRefusalKernel (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperWorkerKernel'+suffix+' (1s)' for suffix in ('', '/root-idle-barrier-after-retirement') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperDaemonKernel'+suffix+' (1s)' for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-barrier-after-retirement (1s)' for case in ('', 'Withdrawal', 'ReleaseRefusal', 'EventRefusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-response-refusal (1s)' for case in ('', 'Withdrawal', 'ReleaseRefusal', 'EventRefusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredInputDownloadFixture (1s)' for _ in range(3)]
        for case in ('TestMeasuredNetworkSessionPaperGuest', 'TestMeasuredNetworkSessionPaperGuestRefusal'):
            rows += [f'--- PASS: {case}/root-result-transfer (1s)' for _ in range(3)]
        rows += ['--- PASS: TestMeasuredNetworkSession'+case+' (1s)' for case in ('Normal', 'RouterLoss', 'StartupRefusal', 'DNSLoss', 'DNSRefreshFailure', 'PreparationTimeout', 'ExecutionTimeout', 'ControllerResourceLoss', 'PaperGuest', 'PaperGuestRefusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredNetworkSessionNormal/'+case+' (1s)' for case in ('local-maximum-refusal', 'local-identity-refusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredNetworkSessionNormal/'+case+' (1s)' for case in ('controller-occupied-refusal', 'controller-exclusive-admission', 'controller-staging-failure', 'controller-busy-refusal', 'controller-cleanup-refusal', 'controller-slot-retirement') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredAuthorityRouteSentryOwnedLaunch/'+case+' (1s)' for case in ('uplink-alias-refusal', 'uplink-journal-refusal', 'uplink-prefix-refusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredBundleJournalKernelRecovery'+suffix+' (1s)' for suffix in ('', '/live-scope', '/retired-scope', '/bounded-no-follow-cleanup', '/foreign-directory-and-record-refusal', '/replaced-directory-refusal', '/mount-boundary-refusal') for _ in range(3)]
        rows += ['--- PASS: TestMeasuredBundleJournalKernelRecovery/'+suffix+' (1s)' for suffix in ('preparation-failure-is-job-local', 'prepared-drift-configuration', 'prepared-drift-resolver', 'prepared-drift-input', 'prepared-drift-identity', 'prepared-drift-private-root') for _ in range(3)]
        report = '\n'.join(rows)
        driver.validate_report(report, '', 0)
        for index in range(len(rows)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                driver.validate_report('\n'.join(rows[:index]+rows[index+1:]), '', 0)
        for stdout, stderr, status in ((report, '', 1), (report+'\n--- SKIP: missing', '', 0),
                                       (report+'\n--- FAIL: ignored', '', 0),
                                       (report+'x'*65536, '', 0), (report, 'x'*65537, 0)):
            with self.assertRaises(AssertionError):
                driver.validate_report(stdout, stderr, status)


if __name__ == '__main__':
    unittest.main()
