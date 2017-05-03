#!/usr/bin/env python3
#
#	Encrypter
#	Copyright (C) 2016 2sh <contact@2sh.me>
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys, os.path
import argparse

import tarfile
import math

import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from subprocess import Popen, PIPE
from getpass import getpass

class Encrypter:
	def __init__(self, key, iv, out_fd, chunk_size=20*512):
		self.encrypter = AES.new(key, AES.MODE_CBC, iv)
		self.out_fd = out_fd

	def write(self, data):
		self.out_fd.write(self.encrypter.encrypt(data))

def calculate_tar_size(path):
	if not os.path.lexists(path):
		raise Exception("{} does not exist")
	
	path_size = sys.getsizeof(path)
	if path_size > 64: # GNU tar path size workaround
		size = 512 + int(512 * math.ceil(path_size/512))
	else:
		size = 0

	if os.path.isfile(path):
		size += os.path.getsize(path)
		size = 512 + int(512 * math.ceil(size/512)) # tar: 512 byte header + data rounded up to a multiple of 512 bytes
		return path, size, 0
	else:
		size += 512 # tar: only the 512 byte header
		return path, size, 1

def passphrase_to_key(passphrase):
	return hashlib.sha256(passphrase.encode('utf-8')).digest()

def create_random_key():
	return get_random_bytes(32)

prefixes = {
	"k": 1,
	"m": 2,
	"g": 3,
	"t": 4,
	"p": 5,
	"e": 6,
	"z": 7,
	"y": 8,
}

def storage_size(value):
	value = value.lower()
	if not value:
		raise Exception("Size not given.")
	if value[-1] == "i":
		if value[-2:-1] in prefixes:
			return int(float(value[:-2]) * 2**(prefixes[value[-2]]*10))
		else:
			raise Exception("Invalid binary prefix.")
	elif value[-1] in prefixes:
		return int(float(value[:-1]) * 1000**prefixes[value[-1]])
	else:
		return int(value)

parser = argparse.ArgumentParser(description="Encrypter")
parser.add_argument("filelist",
	help="A list of all the individual files and folders to be encrypted.")
parser.add_argument("size",
	type=storage_size,
	help="The size of the destination storage")
parser.add_argument("-l",
	dest="filelist_dest",
	metavar="PATH",
	help="The destination file path for the file list of files that did not fit within the size limit.")
parser.add_argument("-i",
	dest="ignore_errors",
	action='store_true',
	help="Continue on non-critical errors (File does not exist).")
parser.add_argument("-k",
	dest="key_command",
	metavar="COMMAND",
	help="Generates a 32-byte encryption key and pipes it into the specified command, e.g. gpg or dd. Otherwise, a passphrase is requested through a prompt.")
args = parser.parse_args()

errors = False

if args.filelist == "-":
	filelist_source = sys.stdin.fileno()
else:
	filelist_source = args.filelist

files = []
for path in filelist_source:
	path = path.strip()
	if not path:
		continue
	try:
		files.append(calculate_tar_size(path))
	except Exception as e:
		print(e)
		errors = True
files.sort(lambda f: (f[2], f[1]), reverse=True) # All directories and such at the start and then files from largest to smallest

if not args.ignore_errors and errors:
	while 1:
		user_input = input("Continue? [y/n]: ").lower()
		if user_input in ["y", "yes"]:
			break
		elif user_input in ["n", "no"]:
			exit()

header = b""
if args.key_command:
	key = create_random_key()
	sp = Popen(args.key_command, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
	data, err = sp.communicate(key)
	if sp.returncode != 0:
		print(err.decode(encoding='UTF-8'), file=sys.stderr)
		exit()
	data_length = len(data)
	if data_length:
		data_length = bytes([(data_length>>(8*i))&0xff for i in range(7,-1,-1)])
		header += data_length + data
else:
	while True:
		passphrase = getpass("Enter a passphrase: ")
		if passphrase == getpass("Enter the same passphrase again: "):
			break
		else:
			print("The passphrases did not match. Try again.\n", file=sys.stderr)

	key = passphrase_to_key(passphrase)

iv = get_random_bytes(AES.block_size)
header += iv

header_size = len(header)

files_next_time = []
dest_size = 512*2 # tar: "The end of an archive is marked by at least two consecutive zero-filled records"
i = 0
while i < len(files):
	size_test = int(10240 * math.ceil((dest_size + files[i][1])/10240)) + header_size # Tarfile buffersize blocks + header size
	if size_test > args.size:
		files_next_time.append(files.pop(i))
	else:
		dest_size += files[i][1]
		i += 1

dest_size = int(10240 * math.ceil(dest_size/10240)) + header_size

if len(files_next_time):
	if not args.filelist_dest:
		print("Filelist destination needs to be specified as the amount of files to be stored exceeds the destination storage size.", file=sys.stderr)
		exit()
	with open(args.filelist_dest, "w") as filelist:
		for file in files_next_time:
			filelist.write(file[0] + "\n")

sys.stdout.buffer.write(header)

encrypter = Encrypter(key, iv, sys.stdout.buffer)
tar = tarfile.open(mode="w|", fileobj=encrypter, encoding="utf-8", format=tarfile.GNU_FORMAT, bufsize=20*512)
for f in files:
	tar.add(f[0], recursive=False)

tar.close()
