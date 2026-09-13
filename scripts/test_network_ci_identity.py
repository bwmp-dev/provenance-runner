"""Keep disposable network evidence immutable and cache work job-local."""
from pathlib import Path
import unittest


class NetworkCIIdentityTests(unittest.TestCase):
    def test_self_hosted_go_jobs_never_archive_shared_build_trees(self):
        workflows = Path(__file__).resolve().parents[1]/'.github/workflows'
        count = 0
        for path in workflows.glob('*.yml'):
            for setup in path.read_text().split('uses: actions/setup-go@v5')[1:]:
                settings = setup.split('      - ', 1)[0]
                self.assertRegex(settings, r'(?m)^          cache: false$', path.name)
                count += 1
        self.assertEqual(count, 5)

    def test_short_expiry_precedes_slow_denial_matrix(self):
        source = (Path(__file__).resolve().parent/'network-policy/acceptance.py').read_text()
        self.assertLess(source.index("evidence['absoluteExpiryClosesEstablishedAndNewFlows']"), source.index("evidence['ipv4Ipv6WholeTuples']"))
        self.assertEqual(source.count("rules['expiry'] = compile_rules('30s')"), 1)
        self.assertEqual(source.count("evidence['absoluteExpiryClosesEstablishedAndNewFlows']"), 1)
        self.assertIn("assert 0<remaining<35, remaining", source)

    def test_cache_is_not_archived_from_the_shared_host(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/network-policy.yml').read_text()
        setup = workflow.split('uses: actions/setup-go@v5', 1)[1].split('      - name:', 1)[0]
        self.assertRegex(setup, r'(?m)^          cache: false$')
        self.assertIn('cache=$(mktemp -d "${RUNNER_TEMP}/network-go-cache.XXXXXXXX")', workflow)
        self.assertIn('echo "GOCACHE=${cache}" >> "${GITHUB_ENV}"', workflow)
        self.assertLess(workflow.index('Isolate disposable Go build cache'), workflow.index('Build and exercise isolated routed packet policy'))

    def test_each_attempt_retains_distinct_source_bound_evidence(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/network-policy.yml').read_text()
        self.assertIn('name: network-policy-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}', workflow)
        self.assertNotRegex(workflow, r'(?m)^\s*overwrite:\s*true\s*$')
        self.assertIn('retention-days: 90', workflow)
        self.assertIn("if: always() && env.PROVENANCE_NETWORK_EVIDENCE != ''", workflow)
        for command in ('acceptance.py --image "$image"', 'dns_acceptance.py --image "$image"', 'acceptance.py --image "$image" --sentry', 'dns_acceptance.py --image "$image" --sentry'):
            self.assertIn(command, workflow)


if __name__ == '__main__':
    unittest.main()
