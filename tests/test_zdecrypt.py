from io import BytesIO
from mock import patch, call

from .base import CellarTests


class CellarDecryptionTests(CellarTests):
    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_base_decrypt(self):
        "PyNaCl byte decryption"
        ciphertext = CellarTests.ciphertext[len(self.cellar.nonce):]
        self.assertEqual(CellarTests.plaintext, self.cellar.decrypt(ciphertext, self.cellar.nonce))

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_base32_dec(self):
        "cellar base32 decryption"
        self.assertEqual(CellarTests.plaintext, self.cellar._dec32(CellarTests.ciphertext32))

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_stream_decrypt(self):
        "test io stream decryption"
        instream, outstream = BytesIO(CellarTests.ciphertext), BytesIO()
        self.cellar.decrypt_stream(instream, outstream)
        self.assertEqual(CellarTests.plaintext, outstream.getvalue())

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_file_decrypt(self):
        infile = self.test_path('foo.enc.txt')
        outfile = self.test_path('foo.txt')
        self.cellar.decrypt_file(infile, outfile)
        self.assertEqual('foo', open(outfile, 'rb').read().strip())

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_dir_decrypt(self):
        indir = self.test_path('level1.enc', CellarTests.level32)
        outdir = self.test_path('level1')
        self.cellar.decrypt_dir(indir, outdir, True)
        self.assertEqual(4, len(self.cellar.logger.call_args_list))
        expected = [
            call(self.test_path('level1', 'level2', 'bar2.txt')),
            call(self.test_path('level1', 'level2', 'foo2.txt')),
            call(self.test_path('level1', 'bar1.txt')),
            call(self.test_path('level1', 'foo1.txt')),
        ]
        self.cellar.logger.assert_has_calls(expected, any_order=True)
