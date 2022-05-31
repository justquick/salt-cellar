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


class Cellar:
    """
    Main encryption class to enc/decrypt streams, files and directories.
    Manages the nacl SecretBox/nonce/keys
    """
    encoder_class = URLSafeBase64Encoder
    block_size = 2 ** 20
    key_size = SecretBox.KEY_SIZE
    prefix = '.enc.'

    def __init__(self, key):
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
        f"""
        Encrypts ciphertext to  plaintext.
        By default it decodes using the {self.encoder_class.__name__}
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

    async def encrypt_file(self, plainfile, cipherfile=None, preserve=False):
        f"""
        Encrypts a plainfile and creates the cipherfile.
        By default it encrypts the filename and file content itself.
        If preserve is True, plainfile is preserved but by default it's deleted
        The new file starts with the '{self.prefix}' prefix
        """
        plainfile = plainfile if isinstance(plainfile, Path) else Path(plainfile)
        if cipherfile is None:
            enc = await self.encrypt(plainfile.name.encode()).decode()
            cipherfile = plainfile.parent / f'{self.prefix}{enc}'
        async with aiofiles.open(cipherfile, 'wb') as fo, aiofiles.open(plainfile, 'rb') as fi:
            chunk = await fi.read(self.block_size)
            while chunk:
                await fo.write(await self.encrypt(chunk, False))
                chunk = await fi.read(self.block_size)
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
        async with aiofiles.open(cipherfile, 'rb') as fi, aiofiles.open(plainfile, 'wb') as fo:
            chunk = await fi.read(self.block_size + 40)
            while chunk:
                await fo.write(await self.decrypt(chunk, False))
                chunk = await fi.read(self.block_size + 40)
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
            tasks.append(self.decrypt_file(path, decpath))

        await asyncio.gather(*tasks)
        #     asyncio.run(main())
        if not preserve:
            rmtree(encdir)
        logger.info(f'Decrypted directory {encdir}')
