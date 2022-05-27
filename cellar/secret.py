import sys
import os
from pathlib import Path

from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import Base32Encoder


def default_logger(msg):
    "Writes to stdout by default"
    sys.stdout.write(msg)
    sys.stdout.write('\n')


def joinpath(path, *args):
    args = [arg.decode() if isinstance(arg, bytes) else arg for arg in args]
    return path.joinpath(*args)


class Cellar(SecretBox):
    def __init__(self, key: bytes, **options):
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
            self.logger(str(e))
            exit(1)

    # def encrypt(self, message: str, nonce: bytes, encoder: Type[_Encoder]) -> bytes:
    #     return super().encrypt(message.encode(), nonce)

    @property
    def nonce(self):
        return random(self.NONCE_SIZE)

    def _enc32(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        elif isinstance(plaintext, Path):
            plaintext = bytes(plaintext)
        return self.encrypt(plaintext, self.nonce, Base32Encoder)

    def _dec32(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        return self.decrypt(ciphertext, encoder=Base32Encoder).decode()

    def encrypt_stream(self, instream, outstream=sys.stdout):
        chunk = instream.read(self.blocksize)
        while chunk:
            outstream.write(self.encrypt(chunk, self.nonce))
            chunk = instream.read(self.blocksize)

    def encrypt_dir(self, directory, outdir=None):
        directory = Path(directory).resolve()
        if outdir is None:
            outdir = directory.parent
        else:
            outdir = Path(outdir).resolve()
            # outdir = os.path.dirname(os.path.abspath(directory))
        root = joinpath(outdir, self._enc32(directory))
        # root = os.path.join(outdir, self._enc32(directory).decode())
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            dirpath = Path(dirpath)
            cryptpath = joinpath(root, self._enc32(dirpath))
            # cryptpath = os.path.join(root, self._enc32(dirpath).decode())
            if not cryptpath.is_dir():  # os.path.isdir(cryptpath):
                cryptpath.mkdir(parents=True, exists_ok=True)
            for filename in filenames:
                # filename = os.path.join(dirpath, filename)
                # cryptname = os.path.join(cryptpath, self._enc32(filename).decode())
                filename = Path(filename)
                filename = joinpath(dirpath, filename)
                cryptname = joinpath(cryptpath, self._enc32(filename))
                self.encrypt_file(filename, cryptname)
        if isinstance(root, bytes):
            root = root.decode()
        self.logger(f'Encrypted {directory} -> {root}')

    def encrypt_file(self, plainfile, cipherfile=None):
        if cipherfile is None:
            cipherfile = self._enc32(plainfile)
        with open(cipherfile, 'wb') as fo, open(plainfile, 'rb') as fi:
            chunk = fi.read(self.blocksize)
            while chunk:
                fo.write(self.encrypt(chunk, self.nonce))
                chunk = fi.read(self.blocksize)
        if self.verbosity:
            if isinstance(cipherfile, bytes):
                cipherfile = cipherfile.decode()
            self.logger(f'Encrypted {plainfile} -> {cipherfile}')

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
            if isinstance(plainfile, bytes):
                plainfile = plainfile.decode()
            self.logger(f'Decrypted {cipherfile} -> {plainfile}')

    def decrypt_dir(self, directory, plainroot=None, lsonly=False):
        directory = Path(directory)
        if not plainroot:
            plainroot = self._dec32(os.path.basename(directory))
        plainroot = Path(plainroot)
        if self.verbosity < 2:
            self.verbosity = 0
        for dirpath, _, filenames in os.walk(directory):
            dirpath = Path(dirpath)
            # path = os.path.split(dirpath)[1]
            path = dirpath.name
            if not path:
                continue
            destpath = Path(self._dec32(path))
            if not destpath.is_dir():  # os.path.isdir(destpath):
                destpath.mkdir(parents=True, exists_ok=True)
            for filename in filenames:
                # filename = Path(filename)
                dest = self._dec32(filename)
                if lsonly:
                    self.logger(dest)
                    continue
                # self.decrypt_file(os.path.join(dirpath, filename), dest)
                self.decrypt_file(joinpath(dirpath, filename), dest)
        if not lsonly:
            # if isinstance(plainroot, bytes):
            #     plainroot = plainroot.decode()
            self.logger(f'Decrypted {directory} -> {plainroot}')
