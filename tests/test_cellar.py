from unittest import TestCase

from cellar import Cellar, DecryptionError


class CellarTestCase(TestCase):
    def test_dual_cellar(self):
        ciphertext = Cellar('key1').encrypt('foobar')
        assert Cellar('key1').decrypt(ciphertext) == b'foobar'

    def test_bad_key(self):
        ciphertext = Cellar('key1').encrypt('foobar')
        cellar = Cellar('key2' * 100)
        self.assertRaises(DecryptionError, cellar.decrypt, ciphertext)
