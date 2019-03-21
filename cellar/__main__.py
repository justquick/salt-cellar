import click
import os
import sys
from six import binary_type
from shutil import rmtree

from cellar.secret import Cellar


@click.group()
@click.version_option()
@click.option('-v', '--verbosity', count=True, help='Output level 1, 2 or 3')
@click.option('-k', '--key', envvar='CELLAR_KEYFILE', type=click.File('rb'),
              help='File path to use for secret key or CELLAR_KEYFILE env var')
@click.pass_context
def cli(ctx, key, verbosity):
    """
    Toolkit for encrypting/decrypting files and directories using symetric encryption.
    Requires a secret keyfile to be passed, otherwise it will prompt for a password to use instead
    """
    def get_cellar():
        secret = key.read() if key else click.prompt('Secret key', hide_input=True, err=True)
        if len(secret) < Cellar.KEY_SIZE:
            secret = secret.ljust(Cellar.KEY_SIZE, '\x00')
        if len(secret) > Cellar.KEY_SIZE:
            secret = secret[:Cellar.KEY_SIZE]
            click.echo('WARN: Key too long, truncating to %d characters' % Cellar.KEY_SIZE, err=True)
        return Cellar(binary_type(secret), verbosity=verbosity)
    ctx.obj = get_cellar


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True, allow_dash=True), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep plain text source content. By default it is deleted once encryption completes successfully.')
@click.pass_context
def encrypt(ctx, preserve, paths):
    "Encrypts given paths. Can be either files or directories"
    cellar = ctx.obj()
    for path in paths:
        if path == '-':
            cellar.encrypt_stream(sys.stdin)
        if os.path.isfile(path):
            cellar.encrypt_file(path)
            if not preserve:
                os.remove(path)
        if os.path.isdir(path):
            cellar.encrypt_dir(path)
            if not preserve:
                rmtree(path)


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True, allow_dash=True), required=True)
@click.option('-p', '--preserve', is_flag=True,
              help='Keep encrypted source content. By default it is deleted once decryption completes successfully.')
@click.pass_context
def decrypt(ctx, preserve, paths):
    "Encrypts given paths. Can be either files or directories"
    cellar = ctx.obj()
    for path in paths:
        if path == '-':
            cellar.decrypt_stream(sys.stdin)
        if os.path.isfile(path):
            cellar.decrypt_file(path)
            if not preserve:
                os.remove(path)
        if os.path.isdir(path):
            cellar.decrypt_dir(path)
            if not preserve:
                rmtree(path)


@cli.command('list')
@click.argument('paths', nargs=-1, type=click.Path(exists=True), required=True)
@click.pass_context
def listcmd(ctx, paths):
    "Lists encrypted path names. Can be either files or directories"
    cellar = ctx.obj()
    for path in paths:
        if os.path.isfile(path):
            cellar.decrypt_file(path, lsonly=True)
        if os.path.isdir(path):
            cellar.decrypt_dir(path, lsonly=True)


if __name__ == '__main__':
    cli(obj=None)
