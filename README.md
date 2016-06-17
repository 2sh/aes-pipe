# Storage Spanning File Encryption
This application is for encrypting files with AES and spanning the encrypted files directly across multiple Blu-Ray/DVD discs or flash drives. The encrypt script accepts a list of files and the size of the first storage destination. Before the encryption, the script determines which files it is able to fit onto the destination and outputs a list of files for the next storage destination.

Use the ```-h``` argument for help.

##Requirements
* Python3
* PyCrypto

##Usage Examples

###Encrypting files spanned across multiple Blu-Ray discs
If no key command is specified, the user is prompted for a passphrase.
```
find /path/photos/ > filelist

python3 encrypt.py -l filelist_rest_1 filelist 25g | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
python3 encrypt.py -l filelist_rest_2 filelist_rest_1 25g | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
python3 encrypt.py -l filelist_rest_3 filelist_rest_2 25g | cdrskin -v driveropts=burnfree -tao dev=/dev/sr0 -
...
```
As the rest filelist is output before the file encryption starts, multiple discs can be written at once.

###Encrypting files spanned across multiple usb sticks
```
python3 encrypt.py -l filelist_rest_1 filelist 16g > /dev/sdX
...
```

###Decrypting files from discs
Using the Blu-Ray discs created in the example above, the following line can be run for each disc.
```
python3 decrypt.py -i /dev/sr0 -o /
```
Files will be output with their original paths.

###Encryption of an auto generated key with a GPG public key

####Prepend encrypted key to header of data output
```
python3 encrypt.py -k "gpg --encrypt --recipient email@example.com" filelist 90g > testfile
```
####Use encrypted key in header of data
```
python3 decrypt.py -p -k "gpg --decrypt" -i testfile -o /path/
```
This needs the ```-p``` argument.

####Output encrypted key file
```
python3 encrypt.py -k "gpg --output encrypted_key.gpg --encrypt --recipient email@example.com" filelist 90g > testfile
```

####Use encrypted key file
```
python3 decrypt.py -k "gpg --decrypt encrypted_key.gpg" -i testfile -o /path/
```
