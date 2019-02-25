import sys
import os
from getpass import getpass
from shutil import rmtree
import warnings
from six import binary_type

from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import Base32Encoder


def log(msg):
    sys.stderr.write('{}\n'.format(msg))


class Cellar(SecretBox):
    BLOCK_SIZE = 2 ** 20  # 1MB

    def __init__(self, **options):
        self.options = options
        key, offset = options['key'], options['offset']
        if not key:
            key = getpass('Key phrase or key file: ')
        if os.path.isfile(key):
            with open(key, 'rb') as keyfile:
                key = keyfile.read()
            if not offset:
                offset = int(getpass('Keyfile offset [0]: ') or 0)
            if offset:
                key = key[offset:offset + self.KEY_SIZE]
        if len(key) < self.KEY_SIZE:
            key = key.ljust(self.KEY_SIZE, '\x00')
        if len(key) > self.KEY_SIZE:
            warnings.warn('Key too long...truncating')
            key = key[:self.KEY_SIZE]
        if binary_type != str:
            key = binary_type(key, 'utf8')
        super(Cellar, self).__init__(key)

    def __getitem__(self, name):
        return self.options[name]

    def __setitem__(self, name, value):
        self.options[name] = value

    def __call__(self):
        action, path, preserve = self['action'], self['path'], self['preserve']
        isfile, isdir = os.path.isfile(path), os.path.isdir(path)
        if isfile:
            if action == 'ls':
                self.decrypt_file(path, lsonly=True)
                return
            if action == 'encrypt':
                self.encrypt_file(path)
            else:
                self.decrypt_file(path)
            if not preserve:
                os.remove(path)
        elif isdir:
            if action == 'ls':
                self.decrypt_dir(path, lsonly=True)
                return
            if action == 'encrypt':
                self.encrypt_dir(path)
            else:
                self.decrypt_dir(path)
            if not preserve:
                rmtree(path)

    def decrypt(self, *args, **kwargs):
        try:
            return super(Cellar, self).decrypt(*args, **kwargs)
        except CryptoError as e:
            log(e)
            exit(1)

    @property
    def nonce(self):
        return random(self.NONCE_SIZE)

    def enc(self, path):
        if binary_type != str:
            path = binary_type(path, 'utf8')
        return self.encrypt(path, self.nonce, Base32Encoder)

    def _dec(self, path):
        return self.decrypt(path, encoder=Base32Encoder)

    def encrypt_file(self, plainfile, cipherfile=None):
        if cipherfile is None:
            cipherfile = self._enc(plainfile)
        with open(cipherfile, 'wb') as fo, open(plainfile, 'rb') as fi:
            chunk = fi.read(self.BLOCK_SIZE)
            while chunk:
                fo.write(self.encrypt(chunk, self.nonce))
                chunk = fi.read(self.BLOCK_SIZE)
        if self['verbosity']:
            if binary_type != str:
                cipherfile = cipherfile.decode()
            log('Encrypted {} -> {}'.format(plainfile, cipherfile))

    def decrypt_file(self, cipherfile, plainfile=None, lsonly=False):
        if plainfile is None:
            plainfile = self._dec(cipherfile)
        if lsonly:
            print(plainfile)
            return
        with open(cipherfile, 'rb') as fi, open(plainfile, 'wb') as fo:
            chunk = fi.read(self.BLOCK_SIZE + 40)
            while chunk:
                fo.write(self.decrypt(chunk))
                chunk = fi.read(self.BLOCK_SIZE + 40)
        if self['verbosity'] and not lsonly:
            if binary_type != str:
                plainfile = plainfile.decode()
            log('Decrypted {} -> {}'.format(cipherfile, plainfile))

    def encrypt_dir(self, directory):
        outdir = os.path.dirname(directory)
        root = os.path.join(outdir, self._enc(directory))
        if self['verbosity'] < 2:
            self['verbosity'] = 0
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
        log('Encrypted {} -> {}'.format(directory, root))

    def decrypt_dir(self, directory, lsonly=False):
        directory = directory.rstrip(os.path.sep)
        plainroot = self._dec(os.path.basename(directory))
        if self['verbosity'] < 2:
            self['verbosity'] = 0
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
            log('Decrypted {} -> {}'.format(directory, plainroot))


