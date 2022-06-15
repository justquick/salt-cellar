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
    long_description_content_type='text/markdown',
    install_requires=['pynacl', 'click', 'aiofiles'],
    entry_points={
        'console_scripts': ['cellar = cellar.cli:cli']
    },
    python_requires='>=3.6',
    project_urls={
        'Documentation': 'https://pynacl-cellar.readthedocs.io/',
        'Source': 'https://github.com/justquick/salt-cellar',
        'Bug Tracker': 'https://github.com/justquick/salt-cellar/issues',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
)
