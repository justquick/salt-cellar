from unittest.mock import patch
from .base import CellarTests


class CryptTest(CellarTests):
    plaintext = b'foobar'
    ciphertext = b'cnJycnJycnJycnJycnJycnJycnJycnJycmDkEdGyR-6iWE3_Mg-GuZ7Ny_qVjg=='

    @patch('cellar.crypt.Cellar.nonce', CellarTests.nonce)
    def test_encrypt(self):
        assert self.ciphertext == self.cellar.encrypt(self.plaintext)
        assert self.cellar.decrypt(self.ciphertext) == self.plaintext
