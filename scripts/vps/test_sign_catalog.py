import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_install import catalog_settings
import updater


class OfflineCatalogSigner(unittest.TestCase):
    def test_signer_rewrites_expiring_urls_and_emits_verifiable_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalogs = root/'catalogs.json'
            catalogs.write_text(json.dumps(catalog_settings()['paperCatalogs']))
            key, output = root/'key.pem', root/'revision.json'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True)
            subprocess.run(['python3',str(Path(__file__).with_name('sign-catalog.py')),
                            '--catalogs',str(catalogs),'--api-origin','https://api.example',
                            '--private-key',str(key),'--output',str(output)],check=True,capture_output=True)
            revision = json.loads(output.read_bytes())
            public = subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'])[-32:]
            with patch.object(updater,'WORK',root):
                updater.verify_catalog(revision,base64.b64encode(public).decode())
            for catalog in revision['catalogs']:
                for asset in (catalog['paper']['artifact'],catalog['java']['artifact'],catalog['probe'],catalog['preparedRuntime']['artifact']):
                    self.assertEqual(asset['uri'],'https://api.example/v1/runner-catalog-assets/'+asset['sha256']+'/'+asset['filename'])


if __name__ == '__main__': unittest.main()
