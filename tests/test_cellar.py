from cellar import Cellar, DecryptionError


class TestCellar:
    async def test_dual_cellar(self):
        ciphertext = await Cellar('key1').encrypt('foobar')
        assert await Cellar('key1').decrypt(ciphertext) == b'foobar'

    async def test_bad_key(self):
        ciphertext = await Cellar('key1').encrypt('foobar')
        cellar = Cellar('key2' * 100)
        try:
            await cellar.decrypt(ciphertext)
        except Exception as exc:
            assert isinstance(exc, DecryptionError)
