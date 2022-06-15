# Salt Cellar Encryption Tool

Salt Cellar is a Python program that protects your files and folders using hard encryption. `cellar` is a command line tool to encrypt and decrypt your files/folders using a secret key and protect them from prying eyes. Files are quickly encrypted/decrypted fully asynchronously using asyncio/aiofiles. 

## Encryption

The hard encryption is accomplished using the [PyNaCl](https://pynacl.readthedocs.io/) package and the [libsodium](https://doc.libsodium.org/) library. The underlying encryption algorithm is [Salsa20](https://cr.yp.to/salsa20.html) which is fast and increases the file size very minimally. By default, `cellar` encrypts the files in place, overwriting the original files with the encrypted version.


> :warning: **DO NOT FORGET YOUR KEY!** This program will make your files unreadable unless you decrypt them. If you lose/forget the secret key then the files will not be recoverable. Use at your own risk



## Keys

A secret key for use with the tool should be 32 bytes long. It can be stored as a file, environment variable or entered in the command line. If the key is too short it will be truncated and if it's too long it will be padded with null bytes.


## Usage

```
Usage: cellar [OPTIONS] COMMAND [ARGS]...

Options:
  --version                Show the version and exit.
  -v, --verbosity          Output level WARN/INFO/DEBUG
  -l, --log-file FILENAME  File path to write logs to
  -k, --key-file FILENAME  File path to use for secret key or CELLAR_KEYFILE env var
  -p, --key-phrase TEXT    Text to use as secret key. Use "-" to read from stdin. Do NOT type your key via command line! It will show in your shell history
  -P, --key-prompt         Prompt for the secret key (default)
  --help                   Show this message and exit.

Commands:
  decrypt  Decrypts given paths.
  encrypt  Encrypts given paths.
```

## Env Vars

`CELLAR_KEYFILE` - A file that contains the content of your private key (32 bytes)

`CELLAR_KEYPHRASE` - A string that contains the content of your private key (32 bytes)

`CELLAR_LOGFILE` - A filename to use for logging

## Example

```
cellar -vv encrypt test-dir/
Secret key: 
WARNING cellar __init__: Key too short, padding to to 32 characters
INFO cellar encrypt_file: Encrypted file test-dir/mypic.jpg
INFO cellar encrypt_dir: Encrypted directory test-dir
```