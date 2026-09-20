import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'namespace_acceptance', Path(__file__).parent / 'network-policy/namespace_acceptance.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class NamespaceAcceptanceTests(unittest.TestCase):
    def test_every_mode_and_repetition_is_required(self):
        rows = [f'--- PASS: Test{case} (1s)' for case in driver.SENTRY_CASES for _ in range(3)]
        report = '\n'.join(rows)
        driver.validate_sentry_report(report, '', 0)
        for index in range(len(rows)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                driver.validate_sentry_report('\n'.join(rows[:index] + rows[index + 1:]), '', 0)
        for output, errors, status in (
            (report, '', 1), (report + '\n--- SKIP: omitted', '', 0),
            (report + '\n--- FAIL: ignored', '', 0),
            (report + '\n' + rows[0], '', 0),
            (report + 'x' * 65536, '', 0), (report, 'x' * 65537, 0),
        ):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                driver.validate_sentry_report(output, errors, status)


if __name__ == '__main__':
    unittest.main()
