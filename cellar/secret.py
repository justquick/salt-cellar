import sys
import os
from six import binary_type

from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import Base32Encoder


def truncate(text, n=10):
    "Truncates a piece of text to at most N characters"
    if len(text) > n:
        return '{}...{}'.format(text[:10], text[-10:])
    return text


def default_logger(msg):
    "Writes to stdout by default"
    sys.stdout.write(msg)
    sys.stdout.write('\n')


class Cellar(SecretBox):
    def __init__(self, key, **options):
        options.setdefault('blocksize', 2 ** 20)  # 1MB
        options.setdefault('verbosity', 3)
        options.setdefault('logger', default_logger)
        for name, value in options.items():
            setattr(self, name, value)
        super(Cellar, self).__init__(key)

    def decrypt(self, *args, **kwargs):
        try:
            return super(Cellar, self).decrypt(*args, **kwargs)
        except CryptoError as e:
            self.logger(e)
            exit(1)

    @property
    def nonce(self):
        return random(self.NONCE_SIZE)

    def _enc32(self, plaintext):
        if binary_type != str:
            plaintext = binary_type(plaintext, 'utf8')
        return self.encrypt(plaintext, self.nonce, Base32Encoder)

    def _dec32(self, ciphertext):
        return self.decrypt(ciphertext, encoder=Base32Encoder)

    def encrypt_stream(self, instream, outstream=sys.stdout):
        chunk = instream.read(self.blocksize)
        while chunk:
            outstream.write(self.encrypt(chunk, self.nonce))
            chunk = instream.read(self.blocksize)

    def encrypt_dir(self, directory, outdir=None):
        if outdir is None:
            outdir = os.path.dirname(os.path.abspath(directory))
        root = os.path.join(outdir, self._enc32(directory))
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            cryptpath = os.path.join(root, self._enc32(dirpath))
            if not os.path.isdir(cryptpath):
                os.makedirs(cryptpath)
            for filename in filenames:
                filename = os.path.join(dirpath, filename)
                cryptname = os.path.join(cryptpath, self._enc32(filename))
                self.encrypt_file(filename, cryptname)
        if binary_type != str:
            root = root.decode()
        self.logger('Encrypted {} -> {}'.format(directory, truncate(root)))

    def encrypt_file(self, plainfile, cipherfile=None):
        if cipherfile is None:
            cipherfile = self._enc32(plainfile)
        with open(cipherfile, 'wb') as fo, open(plainfile, 'rb') as fi:
            chunk = fi.read(self.blocksize)
            while chunk:
                fo.write(self.encrypt(chunk, self.nonce))
                chunk = fi.read(self.blocksize)
        if self.verbosity:
            if binary_type != str:
                cipherfile = cipherfile.decode()
            self.logger('Encrypted {} -> {}'.format(plainfile, truncate(cipherfile)))

    def decrypt_stream(self, instream, outstream=sys.stdout):
        chunk = instream.read(self.blocksize + 40)
        while chunk:
            outstream.write(self.decrypt(chunk))
            chunk = instream.read(self.blocksize + 40)

    def decrypt_file(self, cipherfile, plainfile=None, lsonly=False):
        if plainfile is None:
            plainfile = self._dec32(cipherfile)
        if lsonly:
            self.logger(plainfile)
            return
        with open(cipherfile, 'rb') as fi, open(plainfile, 'wb') as fo:
            chunk = fi.read(self.blocksize + 40)
            while chunk:
                fo.write(self.decrypt(chunk))
                chunk = fi.read(self.blocksize + 40)
        if self.verbosity and not lsonly:
            if binary_type != str:
                plainfile = plainfile.decode()
            self.logger('Decrypted {} -> {}'.format(truncate(cipherfile), plainfile))

    def decrypt_dir(self, directory, plainroot=None, lsonly=False):
        directory = directory.rstrip(os.path.sep)
        if not plainroot:
            plainroot = self._dec32(os.path.basename(directory))
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            path = os.path.split(dirpath)[1]
            if not path:
                continue
            destpath = self._dec32(path)
            if not os.path.isdir(destpath):
                os.makedirs(destpath)
            for filename in filenames:
                dest = self._dec32(filename)
                if lsonly:
                    self.logger(dest)
                    continue
                self.decrypt_file(os.path.join(dirpath, filename), dest)
        if not lsonly:
            if binary_type != str:
                plainroot = plainroot.decode()
            self.logger('Decrypted {} -> {}'.format(truncate(directory), plainroot))
