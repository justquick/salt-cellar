from io import BytesIO
from unittest.mock import patch

import pytest

from cellar.crypt import BaseCellar as Cellar, DecryptionError

from .base import CellarTests


@patch('cellar.crypt.BaseCellar.nonce', CellarTests.nonce)
class TestCellar(CellarTests):
    plaintext = b'foobar'
    ciphertext = b'cnJycnJycnJycnJycnJycnJycnJycnJycmDkEdGyR-6iWE3_Mg-GuZ7Ny_qVjg=='

    async def test_dual_cellar(self):
        ciphertext = await self.cellar.encrypt('foobar')
        assert await self.cellar.decrypt(ciphertext) == b'foobar'

    async def test_bad_key(self):
        ciphertext = await self.cellar.encrypt('foobar')
        cellar = Cellar('key2' * 100)
        with pytest.raises(DecryptionError):
            await cellar.decrypt(ciphertext)

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
