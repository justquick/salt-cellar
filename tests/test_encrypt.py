from io import BytesIO
from mock import patch
from os import walk, listdir

from .base import CellarTests


class CellarEncryptionTests(CellarTests):
    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_base_encrypt(self):
        "PyNaCl byte encryption"
        self.assertEqual(CellarTests.ciphertext,
                         self.cellar.encrypt(CellarTests.plaintext, self.cellar.nonce))

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_base32_enc(self):
        "cellar base32 encryption"
        self.assertEqual(CellarTests.ciphertext32, self.cellar._enc32('abcd'))

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_stream_encrypt(self):
        "test io stream encryption"
        instream, outstream = BytesIO(CellarTests.plaintext), BytesIO()
        self.cellar.encrypt_stream(instream, outstream)
        self.assertEqual(CellarTests.ciphertext, outstream.getvalue())

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_file_encrypt(self):
        infile = self.test_path('foo.txt')
        outfile = self.test_path('foo.enc.txt')
        self.cellar.encrypt_file(infile, outfile)
        self.assertEqual(CellarTests.cipherfoo, open(outfile, 'rb').read())
        msg = self.cellar.logger.call_args[0][0]
        self.assertIn('foo.txt', msg)
        self.assertIn(infile, msg)

    @patch('cellar.secret.random', CellarTests.mocked_random)
    def test_dir_encrypt(self):
        indir = self.test_path('level1')
        outdir = self.test_path('level1.enc')
        self.cellar.encrypt_dir(indir, outdir)
        self.assertEqual(indir, self.cellar._dec32(listdir(outdir)[0]))
        self.assertEqual(4, len(list(walk(outdir))))
