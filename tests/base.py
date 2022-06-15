from pathlib import Path
from hashlib import sha1
from unittest.mock import patch

from nacl.secret import SecretBox

from cellar import crypt


def joinpath(path, *args):
    args = [arg.decode() if isinstance(arg, bytes) else arg for arg in args]
    return path.joinpath(*args)


class CellarTests:
    nonce = b'r' * SecretBox.NONCE_SIZE
    key = b'k' * SecretBox.KEY_SIZE
    testdir = Path(__file__).parent
    cellar_class = crypt.BaseCellar

    @property
    def cellar(self):
        return self.cellar_class(self.key)

    def get_path(self, *args):
        # testdir = os.path.abspath(os.path.dirname(__file__))
        return joinpath(self.testdir, 'data', *args)

    def file_shas(self, adir):
        return self.sha(*[p for p in adir.rglob('*') if p.is_file()])

    def sha(self, *paths):
        if len(paths) == 1:
            path = paths[0]
            if isinstance(path, str):
                path = path.encode()
            return sha1(open(path, 'rb').read()).hexdigest()
        return {str(path.relative_to(self.testdir)): self.sha(path) for path in paths}

    @property
    def patch(self):
        return patch('cellar.crypt.BaseCellar.nonce', CellarTests.nonce)