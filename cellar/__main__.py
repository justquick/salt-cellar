import click
import os
from six import binary_type
from shutil import rmtree

from cellar.secret import Cellar


@click.group()
@click.version_option()
@click.option('-v', '--verbosity', count=True, help='Output level 1, 2 or 3')
@click.option('-k', '--key', envvar='CELLAR_KEYFILE', type=click.File('rb'),
              help='File path to use for secret key or CELLAR_KEYFILE variable')
@click.pass_context
def cli(ctx, key, verbosity):
    """
    Toolkit for encrypting/decrypting files and directories using symetric encryption.
    Requires a secret keyfile to be passed, otherwise it will prompt for a password to use instead
    """
    import ipdb
    ipdb.set_trace()
    secret = key.read() if key else click.prompt('Secret key', hide_input=True)
    if len(secret) < Cellar.KEY_SIZE:
        secret = secret.ljust(Cellar.KEY_SIZE, '\x00')
    if len(secret) > Cellar.KEY_SIZE:
        secret = secret[:Cellar.KEY_SIZE]
        click.echo('WARN: Key too long, truncating to %d characters' % Cellar.KEY_SIZE, err=True)
    ctx.obj = Cellar(binary_type(secret), verbosity=verbosity)


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep plain text source content. By default it is deleted once encryption completes successfully.')
@click.pass_context
def encrypt(ctx, preserve, paths):
    "Encrypts given paths. Can be either files or directories"
    for path in paths:
        if os.path.isfile(path):
            ctx.obj.encrypt_file(path)
            if not preserve:
                os.remove(path)
        if os.path.isdir(path):
            ctx.obj.encrypt_dir(path)
            if not preserve:
                rmtree(path)


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep encrypted source content. By default it is deleted once decryption completes successfully.')
@click.pass_context
def decrypt(ctx, preserve, paths):
    "Encrypts given paths. Can be either files or directories"
    for path in paths:
        if os.path.isfile(path):
            ctx.obj.decrypt_file(path)
            if not preserve:
                os.remove(path)
        if os.path.isdir(path):
            ctx.obj.decrypt_dir(path)
            if not preserve:
                rmtree(path)


if __name__ == '__main__':
    cli(obj=None)
