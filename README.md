# Storage Spanning File Encryption
This application is for encrypting files with AES and spanning them directly
across multiple Blu-Ray/DVD discs, flash drives or files on online storage with
file size limits. The encrypt script accepts a list of files and the size of
the first storage destination. Before the encryption, the script determines
which files it is able to fit onto the destination and outputs a list of files
for the next storage destination.

Use the ```-h``` argument for help.

## Requirements
* Python3
* PyCrypto

## Usage Examples

### Encrypting files spanned across multiple Blu-Ray discs
If no key command is specified, the user is prompted for a passphrase.
```
find /path/photos/ > filelist

python3 encrypt.py -l filelist_rest_1 -s 25g filelist | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
python3 encrypt.py -l filelist_rest_2 -s 25g filelist_rest_1 | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
python3 encrypt.py -l filelist_rest_3 -s 25g filelist_rest_2 | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
...
```
As the rest filelist is output before the file encryption starts, multiple
discs can be written at once.

### Encrypting files spanned across multiple usb sticks
```
python3 encrypt.py -l filelist_rest_1 -s 16g filelist > /dev/sdX
...
```

### Decrypting files from discs
Using the Blu-Ray discs created in the example above, the following line can be
run for each disc.
```
python3 decrypt.py -i /dev/sr0 -o /
```
Files will be output with their original paths.

### Decrypt only specific files and directories
This is useful for recovering deleted items from a backup.
Until the items are found, this will need to be run on each storage area
across which the encrypted data was spanned.
```
python3 decrypt.py -i /dev/sdX | tar -C path/to/output/dir/ -xf - "path/of/dir in archive/" path/of/a_file.png
```
Without the ```-o``` argument,
the unencrypted tar archive data is output to STDOUT.

### Encryption of an auto generated key with a GPG public key

#### Prepend encrypted key to header of data output
```
python3 encrypt.py -k "gpg --encrypt --recipient email@example.com" filelist > testfile
```
#### Use encrypted key in header of data
```
python3 decrypt.py -p -k "gpg --decrypt" -i testfile -o /path/
```
This needs the ```-p``` argument.

#### Output encrypted key file
```
python3 encrypt.py -k "gpg --output encrypted_key.gpg --encrypt --recipient email@example.com" filelist > testfile
```

#### Use encrypted key file
```
python3 decrypt.py -k "gpg --decrypt encrypted_key.gpg" -i testfile -o /path/
```
