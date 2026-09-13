from pathlib import Path
import subprocess
import sys
import unittest

from smoke_execution_identity import allocate


class SmokeIdentityTests(unittest.TestCase):
    def test_cli_rejects_injection_without_echoing_input(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("smoke_execution_identity.py")),
                                 "a" * 40, "hostile-secret\nRUN=1", "1"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "invalid smoke execution identity\n")

    def test_same_run_attempt_has_independent_execution_resources(self):
        values = [allocate("a" * 40, "34737024382", "1") for _ in range(100)]
        for field in ("execution", "artifact", "remoteDirectory", "scope"):
            self.assertEqual(len({value[field] for value in values}), 100)
        for value in values:
            self.assertRegex(value["execution"], r"^[a-f0-9]{32}$")
            for field in ("artifact", "remoteDirectory", "scope"):
                self.assertTrue(value[field].endswith(value["execution"]))
            self.assertRegex(value["remoteDirectory"],
                             r"^/var/lib/provenance-plan0506/ci-smoke/[a-f0-9]{40}-[0-9]+-[0-9]+-[a-f0-9]{32}$")
            self.assertLess(len(value["scope"] + ".scope"), 255)

    def test_reject_hostile_or_unbounded_identifiers(self):
        for index in range(3):
            for invalid in ("", "../", "0", "01", "-1", "1\n", "a;b", "1" * 100, "$(id)"):
                args = ["a" * 40, "12", "1"]
                args[index] = invalid
                with self.subTest(index=index, invalid=invalid), self.assertRaises(ValueError):
                    allocate(*args)

    def test_measured_artifacts_and_staging_keep_distinct_execution_identity(self):
        workflow = Path(__file__).resolve().parents[1].joinpath(".github/workflows/ci.yml").read_text()
        for stem in ("measured-runtime", "runtime-generation", "runtime-generation-work"):
            self.assertIn(stem + '-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${execution}', workflow)
        for stem in ("measured-runtime", "runtime-generation"):
            self.assertIn('name: ' + stem + '-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ env.PROVENANCE_MEASURED_EXECUTION }}', workflow)
        self.assertNotIn('overwrite: true', workflow)


if __name__ == "__main__":
    unittest.main()
