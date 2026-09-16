import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('paper_acceptance', Path(__file__).parent/'network-policy/paper_acceptance.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class RealPaperAcceptanceTests(unittest.TestCase):
    def test_each_repetition_and_retirement_marker_is_mandatory(self):
        rows = ['--- PASS: TestMeasuredPaperRealKernel'+suffix+' (1s)' for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement') for _ in range(3)]
        rows += ['{"'+marker+'": true}' for marker in ('measuredRealPaperCompatibility', 'measuredHostUplinkJournalRetired', 'measuredBundleJournalRetired', 'measuredJobJournalRetired', 'exclusiveMeasuredJobScopesRemoved', 'measuredRoutedOwnedLoopDetached')]
        report = '\n'.join(rows)
        driver.validate_report(report, '', 0)
        for index in range(len(rows)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                driver.validate_report('\n'.join(rows[:index]+rows[index+1:]), '', 0)
        for out, err, code in ((report, '', 1), (report+'\n--- SKIP: missing', '', 0), (report+'\n--- FAIL: missing', '', 0), (report+'x'*65536, '', 0), (report, 'x'*65537, 0)):
            with self.assertRaises(AssertionError):
                driver.validate_report(out, err, code)


if __name__ == '__main__':
    unittest.main()
