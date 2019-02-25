import argparse

from .secret import Cellar


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='cellar', description='''
        Encrypts and decrypts files and directories.
        It uses the PyNaCl and libsodium libraries to implement secret key hard encryption.
    ''')
    parser.add_argument('-v', '--verbosity', action='count', default=0, help='increase output verbosity.')
    parser.add_argument('action', choices=('encrypt', 'decrypt', 'ls'), help='''
        Action to perform. Encrypt will lock up the given path and create a new encrypted.
    ''')
    parser.add_argument('path', type=str, help='the file path location.')
    parser.add_argument('-p', '--preserve', action='store_true',
                        help='keep source content. by default it is deleted once operation completes successfully.')
    parser.add_argument('-k', '--key', type=str, help='secret keyfile (if blank you will be prompted).')
    parser.add_argument('-o', '--offset', type=int, default=0,
                        help='starting offset when reading keyfile (if blank you will be prompted).')
    args = parser.parse_args()

    cellar = Cellar(**vars(args))()
