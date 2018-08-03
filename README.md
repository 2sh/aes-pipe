# AES Pipe
This application/library is for encrypting piped data and was mainly developed to be
used with [limittar](https://github.com/2sh/limittar) for space efficient
data encryption using pipes to remove the need for temporarily storing the
potentially large archives and encrypted data.

## Requirements
* Python 3.4+
* PyCrypto

## Installation
From the Python Package Index:
```
pip install aes-pipe
```

Or download and run:
```
python3 setup.py install
```

## Usage
Use the ```-h``` argument for help:
```
aes-pipe -h
```

### Encrypting data
If no key command is specified, the user is prompted for a passphrase.
```
cat something.tar | aes-pipe > encrypted_tar
```

### Encrypting files spanned across multiple Blu-Ray discs
```
find /path/photos/ -print0 > files

limittar -0 -i files -l remaining1 -s 25025314784 | aes-pipe | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
limittar -0 -i remaining1 -l remaining2 -s 25025314784 | aes-pipe | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
...
```
As the remaining file list is output before the encryption ends, multiple
discs can be written to at once.

*Note that aes-pipe.py prepends a 32 byte nonce to the encrypted output data in
this case which needs to be calculated into the size limit of the tar.*

### Decrypting files from discs
Using the Blu-Ray discs created in the example above, the following line can be
run for each disc.
```
cat /dev/sr0 | aes-pipe -d | tar -xf -
```
Files will be output with their original paths.

### Decrypt only specific files and directories
This is useful for recovering deleted items from a backup.
Until the items are found, this will need to be run on each storage area
across which the encrypted data was spanned.
```
cat /dev/sdX | aes-pipe -d | tar -C path/to/output/dir/ -xf - "path/of/dir in archive/" path/of/a_file.png
```

### Encryption with a GPG public key

#### Output encrypted key file
```
cat something.tar | aes-pipe -c "gpg --output encrypted_key.gpg --encrypt --recipient email@example.com" > encrypted_tar
```
This pipes the encryption key and nonce to the gpg application. This also means
that the nonce is not prepended to the encrypted output which means the output
data size is the same as the input data size.

#### Use encrypted key file
```
cat encrypted_tar | aes-pipe -d -c "gpg --decrypt encrypted_key.gpg" > something.tar
```
