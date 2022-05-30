from unittest import TestCase
from pathlib import Path
from hashlib import sha1

from nacl.secret import SecretBox

from cellar import Cellar


def joinpath(path, *args):
    args = [arg.decode() if isinstance(arg, bytes) else arg for arg in args]
    return path.joinpath(*args)


class CellarTests(TestCase):
    nonce = b'r' * SecretBox.NONCE_SIZE
    key = b'k' * 32
    testdir = Path(__file__).parent

    def setUp(self):
        super(CellarTests, self).setUp()
        self.cellar = Cellar(self.key)

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
