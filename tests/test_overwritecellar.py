from unittest.mock import patch

from cellar.crypt import OverwritePathCellar

from .base import CellarTests


@patch('cellar.crypt.BaseCellar.nonce', CellarTests.nonce)
class TestOverwriteCrypt(CellarTests):
    cellar_class = OverwritePathCellar
    cipherfilesha = '8d0271606d0e549662dbf1c36cb049c6d3a30b04'
    cipherfiles = {
        'data/level1/bar1.txt': 'b9e3b03daad61401cef00d953e69d43a5c73567b',
        'data/level1/foo1.txt': '8d0271606d0e549662dbf1c36cb049c6d3a30b04',
        'data/level1/level2/bar2.txt': 'b9e3b03daad61401cef00d953e69d43a5c73567b',
        'data/level1/level2/foo2.txt': '8d0271606d0e549662dbf1c36cb049c6d3a30b04',
    }
    plainfiles = {
        'data/level1/bar1.txt': 'e242ed3bffccdf271b7fbaf34ed72d089537b42f',
        'data/level1/foo1.txt': 'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15',
        'data/level1/level2/bar2.txt': 'e242ed3bffccdf271b7fbaf34ed72d089537b42f',
        'data/level1/level2/foo2.txt': 'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15'
    }

    async def test_encrypt_file(self):
        plainfile = self.get_path('foo.txt')
        plainsha = self.sha(plainfile)
        await self.cellar.encrypt_file(plainfile)
        cipherfile = self.get_path('foo.txt')
        assert cipherfile.is_file()
        assert self.sha(cipherfile) == self.cipherfilesha
        await self.cellar.decrypt_file(cipherfile)
        assert plainsha == self.sha(plainfile)

    async def test_encrypt_dir(self):
        plaindir = self.get_path('level1')
        await self.cellar.encrypt_dir(plaindir)
        cipherdir = self.get_path('level1')
        assert cipherdir.is_dir()
        cfiles = self.file_shas(cipherdir)
        assert cfiles == self.cipherfiles
        await self.cellar.decrypt_dir(cipherdir)
        assert self.plainfiles == self.file_shas(plaindir)
