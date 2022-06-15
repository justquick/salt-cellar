import os
from setuptools import setup

from cellar import __version__ as pkg



def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        return open(filepath).read()
    except IOError:
        return ''


setup(
    name=pkg.__name__,
    version=pkg.__version__,
    packages=['cellar'],
    author=pkg.__author__,
    author_email=pkg.__author_email__,
    license=pkg.__license__,
    description=pkg.__description__,
    long_description=read_file('README.md'),
    install_requires=['pynacl', 'click', 'aiofiles'],
    entry_points={
        'console_scripts': ['cellar = cellar.cli:cli']
    },
)
