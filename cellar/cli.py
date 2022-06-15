import click
import sys
from pathlib import Path
import asyncio


from cellar.crypt import OverwritePathCellar as Cellar, DecryptionError
from cellar.log import setup


USAGE = """
Toolkit for encrypting/decrypting files and directories using symetric (secret key) encryption.
Requires a secret key to be passed either by file, prompt or read from stdin.
The key must be 32 bytes long.
If key is too short, it will be padded by null bytes.
If key is too long, it will be truncated.
"""




@click.group('cellar')
@click.version_option()
@click.option('-v', '--verbosity', default=1, count=True, help='Output level WARN/INFO/DEBUG')
@click.option('-l', '--log-file', envvar='CELLAR_LOGFILE', type=click.File('w'),
              help='File path to write logs to')
@click.option('-k', '--key-file', envvar='CELLAR_KEYFILE', type=click.File('rb'),
              help='File path to use for secret key or CELLAR_KEYFILE env var')
@click.option('-p', '--key-phrase', envvar='CELLAR_KEYPHRASE', default=None,
              help='Text to use as secret key. Use "-" to read from stdin. Do NOT type your key via command line! It will show in your shell history')
@click.option('-P', '--key-prompt', is_flag=True,
              help='Prompt for the secret key (default)')
@click.pass_context
def cli(ctx, key_prompt, key_phrase, key_file, log_file, verbosity):
    ctx.ensure_object(object)
    setup(verbosity, log_file)
    if key_prompt:
        secret = click.prompt('Secret key', hide_input=True, err=True).encode()
    elif key_phrase:
        secret = sys.stdin.buffer.read() if key_phrase == '-' else key_phrase.encode()
    elif key_file:
        secret = key_file.read()
    ctx.obj = Cellar(secret)


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True, allow_dash=True, path_type=Path), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep plain text source content. By default it is deleted once encryption completes successfully.')
@click.pass_context
def encrypt(ctx, preserve, paths):
    "Encrypts given paths. Can be either files or directories"
    for path in paths:
        if str(path) == '-':
            main = ctx.obj.encrypt_stream(sys.stdin.buffer)
        elif path.is_file():
            main = ctx.obj.encrypt_file(path)
        elif path.is_dir():
            main = ctx.obj.encrypt_dir(path)
        asyncio.get_event_loop().run_until_complete(main)


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True, allow_dash=True, path_type=Path), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep encrypted source content. By default it is deleted once decryption completes successfully.')
@click.pass_context
def decrypt(ctx, preserve, paths):
    "Decrypts given paths. Can be either files or directories"
    for path in paths:
        if str(path) == '-':
            main = ctx.obj.decrypt_stream(sys.stdin.buffer)
        elif path.is_file():
            main = ctx.obj.decrypt_file(path)
        elif path.is_dir():
            main = ctx.obj.decrypt_dir(path)
        try:
            asyncio.get_event_loop().run_until_complete(main)
        except DecryptionError as exc:
            click.secho(exc, fg='red')
            raise click.Abort


if __name__ == '__main__':
    from ipdb import launch_ipdb_on_exception
    with launch_ipdb_on_exception():
        cli(obj=None)
