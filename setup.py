import os
from setuptools import setup


def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        return open(filepath).read()
    except IOError:
        return ''


setup(
    name='Salt Cellar',
    packages=['cellar'],
    install_requires=read_file('requirements.txt'),
    entry_points={
        'console_scripts': ['cellar = cellar.__main__:main']
    },
)
