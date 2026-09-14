import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('measured_network_acceptance', Path(__file__).parent/'network-policy/measured_acceptance.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class MeasuredAcceptanceTests(unittest.TestCase):
    def test_both_repeated_real_cases_and_cleanup_are_mandatory(self):
        rows = ['--- PASS: TestMeasuredAuthorityRouteSentry'+case+' (1s)' for case in ('Withdrawal', 'Expiry') for _ in range(3)]
        rows += ['{"measuredRoutedOwnedLoopDetached": true}']
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
