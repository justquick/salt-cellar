from .base import CellarTests
from mock import patch


class CellarPatchTests(CellarTests):
    def test_nonce(self):
        "nonce entropy"
        self.assertNotEqual(self.cellar.nonce, self.cellar.nonce)

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_patch(self):
        "patching random func & nonce"
        self.assertEqual(self.cellar.nonce, self.cellar.nonce)
