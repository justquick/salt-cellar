from unittest.mock import patch
from io import BytesIO

from .base import CellarTests
import pytest


@pytest.mark.asyncio
@patch('cellar.crypt.Cellar.nonce', CellarTests.nonce)
class TestCrypt(CellarTests):
    plaintext = b'foobar'
    ciphertext = b'cnJycnJycnJycnJycnJycnJycnJycnJycmDkEdGyR-6iWE3_Mg-GuZ7Ny_qVjg=='
    cipherfilename = 'cnJycnJycnJycnJycnJycnJycnJycnJy_5toRIJOTeFTl8Y_rqJ9l57Ny7aAhMc='
    cipherfilesha = '8d0271606d0e549662dbf1c36cb049c6d3a30b04'
    cipherdirname = 'cnJycnJycnJycnJycnJycnJycnJycnJyMeNcp6vJ7VQqxRg5ez0TD5TH0v2YzQ=='
    plainfiles = {
        'data/level1/bar1.txt': 'e242ed3bffccdf271b7fbaf34ed72d089537b42f',
        'data/level1/foo1.txt': 'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15',
        'data/level1/level2/foo2.txt': 'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15',
        'data/level1/level2/bar2.txt': 'e242ed3bffccdf271b7fbaf34ed72d089537b42f'
    }
    cipherfiles = {
        'data/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyMeNcp6vJ7VQqxRg5ez0TD5TH0v2YzQ==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyNlD84bkNMjgz5Y4GhtGuR5TH0v2Yzg==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyogrmR9xua3CRFbaCNaAqB5rD1qraiMto':
        'b9e3b03daad61401cef00d953e69d43a5c73567b',
        'data/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyMeNcp6vJ7VQqxRg5ez0TD5TH0v2YzQ==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyNlD84bkNMjgz5Y4GhtGuR5TH0v2Yzg==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyvScxXfEl3o551U8Wd0ki9Z7Ny6raiMto':
        '8d0271606d0e549662dbf1c36cb049c6d3a30b04',
        'data/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyMeNcp6vJ7VQqxRg5ez0TD5TH0v2YzQ==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyH0Ve5SB8mhyro4jvulBsDtY=/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyBNDXA5iLYlAbSKvumWcn45rD1qnaiMto':
        'b9e3b03daad61401cef00d953e69d43a5c73567b',
        'data/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyMeNcp6vJ7VQqxRg5ez0TD5TH0v2YzQ==/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyH0Ve5SB8mhyro4jvulBsDtY=/.enc.cnJycnJycnJycnJycnJycnJycnJycnJyGu0iGa1C1W4DCEWC2xAf0Z7Ny6naiMto':
        '8d0271606d0e549662dbf1c36cb049c6d3a30b04'
    }

    async def test_encrypt(self):
        assert self.ciphertext == await self.cellar.encrypt(self.plaintext)
        assert await self.cellar.decrypt(self.ciphertext) == self.plaintext

    async def test_encrypt_stream(self):
        instream, outstream = BytesIO(self.plaintext), BytesIO()
        await self.cellar.encrypt_stream(instream, outstream, True)
        assert self.ciphertext == outstream.getvalue()

        instream, outstream = BytesIO(self.ciphertext), BytesIO()
        await self.cellar.decrypt_stream(instream, outstream, True)
        assert self.plaintext == outstream.getvalue()

    async def test_encrypt_file(self):
        plainfile = self.get_path('foo.txt')
        plainsha = self.sha(plainfile)
        await self.cellar.encrypt_file(plainfile)
        cipherfile = self.get_path(f'{self.cellar.prefix}{self.cipherfilename}')
        assert cipherfile.is_file()
        assert self.sha(cipherfile) == self.cipherfilesha
        await self.cellar.decrypt_file(cipherfile)
        assert plainsha == self.sha(plainfile)

    async def test_encrypt_dir(self):
        plaindir = self.get_path('level1')
        await self.cellar.encrypt_dir(plaindir)
        cipherdir = self.get_path(f'{self.cellar.prefix}{self.cipherdirname}')
        assert cipherdir.is_dir()
        cfiles = self.file_shas(cipherdir)
        assert cfiles == self.cipherfiles
        await self.cellar.decrypt_dir(cipherdir)
        assert self.plainfiles == self.file_shas(plaindir)
