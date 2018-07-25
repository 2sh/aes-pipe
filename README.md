# AES Pipe
This application is for encrypting piped data and was mainly developed to be
used with [limittar.py](https://github.com/2sh/limittar.py) for space efficient
data encryption using pipes to remove the need for temporarily storing the
potentially large archives and encrypted data.

Use the ```-h``` argument for help:
```
python3 aes-pipe.py -h
```

## Requirements
* Python 3
* PyCrypto

## Usage Examples

### Encrypting data
If no key command is specified, the user is prompted for a passphrase.
```
cat something.tar | python3 aes-pipe.py > encrypted_tar
```

### Encrypting files spanned across multiple Blu-Ray discs
```
find /path/photos/ -print0 > files

python3 limittar.py -0 -i files -l remaining1 -s 25025314784 | python3 aes-pipe.py | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
python3 limittar.py -0 -i remaining1 -l remaining2 -s 25025314784 | python3 aes-pipe.py | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
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
cat /dev/sr0 | python3 aes-pipe.py -d | tar -xf -
```
Files will be output with their original paths.

### Decrypt only specific files and directories
This is useful for recovering deleted items from a backup.
Until the items are found, this will need to be run on each storage area
across which the encrypted data was spanned.
```
cat /dev/sdX | python3 aes-pipe.py -d | tar -C path/to/output/dir/ -xf - "path/of/dir in archive/" path/of/a_file.png
```

### Encryption with a GPG public key

#### Output encrypted key file
```
cat something.tar | python3 aes-pipe.py -c "gpg --output encrypted_key.gpg --encrypt --recipient email@example.com" > encrypted_tar
```
This pipes the encryption key and nonce to the gpg application. This also means
that the nonce is not prepended to the encrypted output which means the output
data size is the same as the input data size.

#### Use encrypted key file
```
cat encrypted_tar | python3 python3 aes-pipe.py -d -c "gpg --decrypt encrypted_key.gpg" > something.tar
```
