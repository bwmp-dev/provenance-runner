import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('job_cgroup_acceptance', Path(__file__).parent/'network-policy/job_cgroup_acceptance.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class JobCgroupAcceptanceTests(unittest.TestCase):
    def test_three_real_cases_required(self):
        row = '--- PASS: TestJobCgroupKernelLifecycle (1s)\n'
        recovery = '--- PASS: TestJobCgroupJournalKernelRecovery (1s)\n'
        valid = row*3+recovery*3
        driver.validate_report(valid, '', 0)
        with self.assertRaises(AssertionError):
            driver.validate_report(row*3, '', 0)
        with self.assertRaises(AssertionError):
            driver.validate_report(recovery*3, '', 0)
        for stdout, stderr, status in ((row*2+recovery*3, '', 0), (row*4+recovery*3, '', 0),
                                       (valid+'--- SKIP: missing', '', 0),
                                       (valid+'--- FAIL: failed', '', 0),
                                       (valid, '', 1), (valid+'x'*65537, '', 0),
                                       (valid, 'x'*65537, 0)):
            with self.assertRaises(AssertionError):
                driver.validate_report(stdout, stderr, status)


if __name__ == '__main__':
    unittest.main()
