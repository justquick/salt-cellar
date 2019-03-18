import sys
import os
from six import binary_type

from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import Base32Encoder


def truncate(path):
    return '{}...{}'.format(path[:10], path[-10:])


class Cellar(SecretBox):
    BLOCK_SIZE = 2 ** 20  # 1MB

    def __init__(self, key, **options):
        self.verbosity = 1
        self.log = lambda msg: sys.stdout.write('{}\n'.format(msg))
        for name, value in options.items():
            setattr(self, name, value)
        super(Cellar, self).__init__(key)

    #
    # def __call__(self):
    #     action, path, preserve = self['action'], self['path'], self['preserve']
    #     isfile, isdir = os.path.isfile(path), os.path.isdir(path)
    #     if isfile:
    #         if action == 'ls':
    #             self.decrypt_file(path, lsonly=True)
    #             return
    #         if action == 'encrypt':
    #             self.encrypt_file(path)
    #         else:
    #             self.decrypt_file(path)
    #         if not preserve:
    #             os.remove(path)
    #     elif isdir:
    #         if action == 'ls':
    #             self.decrypt_dir(path, lsonly=True)
    #             return
    #         if action == 'encrypt':
    #             self.encrypt_dir(path)
    #         else:
    #             self.decrypt_dir(path)
    #         if not preserve:
    #             rmtree(path)

    def decrypt(self, *args, **kwargs):
        try:
            return super(Cellar, self).decrypt(*args, **kwargs)
        except CryptoError as e:
            self.log(e)
            exit(1)

    @property
    def nonce(self):
        return random(self.NONCE_SIZE)

    def _enc(self, path):
        if binary_type != str:
            path = binary_type(path, 'utf8')
        return self.encrypt(path, self.nonce, Base32Encoder)

    def _dec(self, path):
        return self.decrypt(path, encoder=Base32Encoder)

    def encrypt_stream(self, stream):
        chunk = stream.read(self.BLOCK_SIZE)
        while chunk:
            sys.stdout.write(self.encrypt(chunk, self.nonce))
            chunk = stream.read(self.BLOCK_SIZE)

    def encrypt_dir(self, directory):
        outdir = os.path.dirname(os.path.abspath(directory))
        root = os.path.join(outdir, self._enc(directory))
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            cryptpath = os.path.join(root, self._enc(dirpath))
            os.makedirs(cryptpath)
            for filename in filenames:
                filename = os.path.join(dirpath, filename)
                cryptname = os.path.join(cryptpath, self._enc(filename))
                if os.path.exists(cryptname):
                    raise IOError('Collision: %s' % cryptname)
                self.encrypt_file(filename, cryptname)
        if binary_type != str:
            root = root.decode()
        self.log('Encrypted {} -> {}'.format(directory, truncate(root)))

    def encrypt_file(self, plainfile, cipherfile=None):
        if cipherfile is None:
            cipherfile = self._enc(plainfile)
        with open(cipherfile, 'wb') as fo, open(plainfile, 'rb') as fi:
            chunk = fi.read(self.BLOCK_SIZE)
            while chunk:
                fo.write(self.encrypt(chunk, self.nonce))
                chunk = fi.read(self.BLOCK_SIZE)
        if self.verbosity:
            if binary_type != str:
                cipherfile = cipherfile.decode()
            self.log('Encrypted {} -> {}'.format(plainfile, truncate(cipherfile)))

    def decrypt_stream(self, stream):
        chunk = stream.read(self.BLOCK_SIZE + 40)
        while chunk:
            sys.stdout.write(self.decrypt(chunk))
            chunk = stream.read(self.BLOCK_SIZE + 40)

    def decrypt_file(self, cipherfile, plainfile=None, lsonly=False):
        if plainfile is None:
            plainfile = self._dec(cipherfile)
        if lsonly:
            self.log(plainfile)
            return
        with open(cipherfile, 'rb') as fi, open(plainfile, 'wb') as fo:
            chunk = fi.read(self.BLOCK_SIZE + 40)
            while chunk:
                fo.write(self.decrypt(chunk))
                chunk = fi.read(self.BLOCK_SIZE + 40)
        if self.verbosity and not lsonly:
            if binary_type != str:
                plainfile = plainfile.decode()
            self.log('Decrypted {} -> {}'.format(truncate(cipherfile), plainfile))


    def decrypt_dir(self, directory, lsonly=False):
        directory = directory.rstrip(os.path.sep)
        plainroot = self._dec(os.path.basename(directory))
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            path = os.path.split(dirpath)[1]
            if not path:
                continue
            destpath = self._dec(path)
            if not os.path.isdir(destpath):
                os.makedirs(destpath)
            for filename in filenames:
                dest = self._dec(filename)
                if lsonly:
                    print(dest)
                    continue
                self.decrypt_file(os.path.join(dirpath, filename), dest)
        if not lsonly:
            if binary_type != str:
                plainroot = plainroot.decode()
            self.log('Decrypted {} -> {}'.format(truncate(directory), plainroot))
