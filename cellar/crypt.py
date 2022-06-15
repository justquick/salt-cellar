from pathlib import Path
import sys
from shutil import rmtree
import asyncio

from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import URLSafeBase64Encoder, RawEncoder
import aiofiles

from .log import logger


class DecryptionError(Exception):
    pass


class BaseCellar:
    """
    Main encryption class to enc/decrypt streams, files and directories.
    Manages the nacl SecretBox/nonce/keys
    """

    def __init__(self, key, encoder_class=URLSafeBase64Encoder, block_size=2 ** 20, concurrency=100):
        self.encoder_class = encoder_class
        self.block_size = block_size
        self.semaphore = asyncio.Semaphore(concurrency)
        self.key_size = SecretBox.KEY_SIZE
        self.total_bytes = 0
        if isinstance(key, str):
            key = key.encode()
        if len(key) < self.key_size:
            key = key.ljust(self.key_size, b'\x00')
            logger.warning(f'Key too short, padding to to {self.key_size} characters')
        elif len(key) > self.key_size:
            key = key[:self.key_size]
            logger.warning(f'Key too long, truncating to {self.key_size} characters')
        self.box = SecretBox(key)

    @property
    def nonce(self):
        """
        Random nonce to fix box size
        """
        return random(self.box.NONCE_SIZE)

    async def encrypt(self, plaintext, encode=True):
        f"""
        Encrypts plaintext to ciphertext.
        By default it encodes using the {self.encoder_class.__name__}
        """
        encoder = self.encoder_class if encode else RawEncoder
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        return self.box.encrypt(plaintext, self.nonce, encoder())

    async def decrypt(self, ciphertext, decode=True):
        """
        Encrypts ciphertext to  plaintext.
        By default it decodes using the URLSafeBase64Encoder
        Catches any errors (like bad dec key) and logs them before exiting
        """
        encoder = self.encoder_class if decode else RawEncoder
        try:
            return self.box.decrypt(ciphertext, encoder=encoder)
        except CryptoError as exc:
            msg = f'{exc}. Make sure the decryption key is correct'
            logger.critical(msg)
            raise DecryptionError(msg)

    async def encrypt_stream(self, instream, outstream=sys.stdout.buffer, encode=False):
        """
        Encrypts a stream and outputs it to another (default stdout)
        """
        chunk = instream.read(self.block_size)
        while chunk:
            outstream.write(await self.encrypt(chunk, encode))
            chunk = instream.read(self.block_size)

    async def decrypt_stream(self, instream, outstream=sys.stdout.buffer, decode=False):
        """
        Decrypts a stream and outputs it to another (default stdout)
        """
        chunk = instream.read(self.block_size + 40)
        while chunk:
            outstream.write(await self.decrypt(chunk, decode))
            chunk = instream.read(self.block_size + 40)

    async def read_write_crypto(self, infile, outfile, encrypt=True):
        method = self.encrypt if encrypt else self.decrypt
        block_size = self.block_size if encrypt else self.block_size + 40
        async with self.semaphore:
            async with aiofiles.open(infile, 'rb') as fi, aiofiles.open(outfile, 'wb') as fo:
                chunk = await fi.read(block_size)
                while chunk:
                    self.total_bytes += len(chunk)
                    await fo.write(await method(chunk, False))
                    chunk = await fi.read(block_size)

    async def map_crypto(self, func, iters):
        await asyncio.gather(*(func(arg) for arg in iters))


class OverwritePathCellar(BaseCellar):
    async def encrypt_file(self, plainfile, preserve=None):
        tmpfile = plainfile.with_suffix(f'{plainfile.suffix}.enc')
        await self.read_write_crypto(plainfile, tmpfile)
        tmpfile.replace(plainfile)
        logger.info(f'Encrypted file {plainfile}')

    async def decrypt_file(self, cipherfile, preserve=None):
        tmpfile = cipherfile.with_suffix(f'{cipherfile.suffix}.dec')
        await self.read_write_crypto(cipherfile, tmpfile, False)
        tmpfile.replace(cipherfile)
        logger.info(f'Decrypted file {cipherfile}')

    async def encrypt_dir(self, plaindir, preserve=False):
        await self.map_crypto(self.encrypt_file, (path for path in plaindir.rglob('*') if path.is_file()))
        logger.info(f'Encrypted directory {plaindir}')

    async def decrypt_dir(self, cipherdir, preserve=False):
        await self.map_crypto(self.decrypt_file, (path for path in cipherdir.rglob('*') if path.is_file()))
        logger.info(f'Decrypted directory {cipherdir}')


class EncryptedPathCellar(BaseCellar):
    """
    Cellar that encrypts the filenames as well as the content
    """
    prefix = '.enc.'

    async def encrypt_file(self, plainfile, cipherfile=None, preserve=False):
        f"""
        Encrypts a plainfile and creates the cipherfile.
        By default it encrypts the filename and file content itself.
        If preserve is True, plainfile is preserved but by default it's deleted
        The new file starts with the '{self.prefix}' prefix
        """
        plainfile = plainfile if isinstance(plainfile, Path) else Path(plainfile)
        if cipherfile is None:
            enc = await self.encrypt(plainfile.name.encode())
            enc = enc.decode()
            cipherfile = plainfile.parent / f'{self.prefix}{enc}'
        await self.read_write_crypto(plainfile, cipherfile)
        logger.debug(f'Encrypted file {plainfile} -> {cipherfile}')
        if not preserve:
            plainfile.unlink()
        return cipherfile

    async def decrypt_file(self, cipherfile, plainfile=None, preserve=False):
        f"""
        Decrypts a cipherfile into the plainfile.
        By default it decrypts the filename and file content itself.
        If preserve is True, cipherfile is preserved but by default it's deleted
        The cipherfile file starts with the '{self.prefix}' prefix
        """
        cipherfile = cipherfile if isinstance(cipherfile, Path) else Path(cipherfile)
        dec = await self.decrypt(cipherfile.name[len(self.prefix):])
        dec = dec.decode()
        if plainfile is None:
            plainfile = cipherfile.parent / dec
        await self.read_write_crypto(cipherfile, plainfile, False)
        if not preserve:
            cipherfile.unlink()
        logger.debug(f'Decrypted file {cipherfile} -> {plainfile}')
        return plainfile

    async def encrypt_dir(self, plaindir, preserve=False):
        """
        Encrypts entire directory with all file/dir names and file content
        If preserve is True, plaindir is preserved but by default it's deleted
        """
        plaindir = plaindir if isinstance(plaindir, Path) else Path(plaindir)
        encplain = await self.encrypt(plaindir.name.encode())
        encbase = plaindir.parent / f'{self.prefix}{encplain.decode()}'
        tasks = []
        for path in plaindir.rglob('*'):
            if path.name.startswith(self.prefix) or path.is_dir():
                # dont double encrypt files, skip dirs
                continue
            relpath = path.relative_to(plaindir)
            encparent = await self.encrypt(bytes(relpath.parent))
            encparent = encparent.decode()
            encname = await self.encrypt(path.name.encode())
            encname = encname.decode()
            cipherfile = encbase / f'{self.prefix}{encparent}' / f'{self.prefix}{encname}'
            cipherfile.parent.mkdir(parents=True, exist_ok=True)
            tasks.append(self.encrypt_file(path, cipherfile, preserve))
        await asyncio.gather(*tasks)
        if not preserve:
            rmtree(plaindir)
        logger.info(f'Encrypted directory {plaindir}')
        return encbase

    async def decrypt_dir(self, encdir, preserve=False):
        """
        Decrypts entire directory with all file/dir names and file content
        If preserve is True, encdir is preserved but by default it's deleted
        """
        encdir = encdir if isinstance(encdir, Path) else Path(encdir)
        decbase = await self.decrypt(encdir.name[len(self.prefix):])
        decbase = encdir.parent / Path(decbase.decode())
        tasks = []
        for path in encdir.rglob('*'):
            if path.is_dir():
                continue
            relpath = path.relative_to(encdir)
            decparent = await self.decrypt(str(relpath.parent)[len(self.prefix):].encode())
            decparent = decparent.decode()
            decname = await self.decrypt(relpath.name[len(self.prefix):])
            decname = decname.decode()
            decpath = decbase / decparent / decname
            decpath.parent.mkdir(parents=True, exist_ok=True)
            tasks.append(self.decrypt_file(path, decpath, preserve))

        await asyncio.gather(*tasks)
        #     asyncio.run(main())
        if not preserve:
            rmtree(encdir)
        logger.info(f'Decrypted directory {encdir}')
        return decbase
