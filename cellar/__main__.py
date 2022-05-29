import sys
import ipdb

from .cli import cli


if __name__ == '__main__':
    with ipdb.launch_ipdb_on_exception():
        cli(sys.argv[1:])
