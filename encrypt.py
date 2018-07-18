#!/usr/bin/env python3
#
#	Encrypter
#	Copyright (C) 2016-2018 2sh <contact@2sh.me>
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
from Crypto.Util import Counter

from subprocess import Popen, PIPE
from getpass import getpass

from queue import Queue
from threading import Thread

class FileEncrypter:
	def __init__(self, out_fd, key, iv):
		self.out_fd = out_fd
		ctr = Counter.new(64, prefix=iv)
		self.encrypter = AES.new(key, AES.MODE_CTR, counter=ctr)

	def write(self, data):
		self.out_fd.write(self.encrypter.encrypt(data))

def calculate_tar_file_size(path):
	if not os.path.lexists(path):
		raise Exception("{} does not exist".format(path))
	
	path_size = sys.getsizeof(path)
	if path_size > 64: # GNU tar path size workaround
		size = 512 + 512 * int(math.ceil(path_size/512))
	else:
		size = 0

	if os.path.isfile(path):
		file_size = os.path.getsize(path)
		# 512 byte header + data rounded up to a multiple of 512 bytes
		size += 512 + 512 * int(math.ceil(file_size)/512)
		return path, size, 0
	else:
		# only the 512 byte header
		size += 512
		return path, size, 1

def calculate_tar_size(data_size, blocking_factor=20):
	# End of archive marked by two consecutive zero-filled records
	return int((blocking_factor*512) *
		math.ceil((data_size + 512*2)/(blocking_factor*512)))

class FilelistOutFile:
	def __init__(self, path):
		self.path = path
		self.f = None
		try:
			open(self.path, "r").close()
		except:
			pass
		else:
			self.f = open(self.path, "w")
	
	def write(self, data):
		if self.path:
			if not self.f:
				self.f = open(self.path, "w")
			self.f.write(data)
		else:
			print(data, file=sys.stderr)
	
	def close(self):
		if self.f:
			self.f.close()

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
parser.add_argument("-l",
	dest="filelist_out",
	metavar="PATH",
	help="File to which to write list of files that did not "
		"fit within the size limit or failed.")
parser.add_argument("-s",
	dest="size",
	type=storage_size,
	help="The size of the destination storage.")
parser.add_argument("-u",
	dest="no_underrun",
	action="store_true",
	help="Attempt to prevent a buffer underrun. If the buffer is empty, "
		"the output is halted and the paths of any remaining files "
		"are written to the out file list.")
parser.add_argument("-f",
	dest="fill",
	action="store_true",
	help="Fill any remaining space on the destination storage "
		"with random bytes.")
parser.add_argument("-c",
	dest="key_command",
	metavar="COMMAND",
	help="Generates a 32-byte encryption key and pipes it into "
		"the specified command, e.g. gpg or dd. Otherwise, "
		"a passphrase is requested through a prompt.")
parser.add_argument("-k",
	dest="key_size",
	metavar="SIZE",
	type=lambda x: int(x)//8,
	default=32,
	help="The AES key size in bits: 128, 192 or 256 [Default: 256].")

args = parser.parse_args()

if args.filelist == "-":
	filelist_source = sys.stdin.fileno()
else:
	filelist_source = args.filelist

header = b""
if args.key_command:
	key = get_random_bytes(args.key_size)
	sp = Popen(args.key_command, shell=True, stdin=PIPE, stdout=PIPE)
	data, _ = sp.communicate(key)
	if sp.returncode != 0:
		exit()
	data_length = len(data)
	if data_length:
		header += data_length.to_bytes(8, byteorder="big") + data
else:
	while True:
		passphrase = getpass("Enter a passphrase: ")
		if passphrase == getpass("Enter the same passphrase again: "):
			break
		else:
			print("The passphrases did not match. Try again.",
				file=sys.stderr)
	key = hashlib.sha256(passphrase.encode("utf-8")).digest()[:args.key_size]

iv = get_random_bytes(8)
header += iv
header_size = len(header)

if args.size:
	max_tar_size = args.size-header_size
else:
	max_tar_size = None

paths_to_write = Queue()

files_size = 0

files_in = open(filelist_source, "r")
files_out = FilelistOutFile(args.filelist_out)

sys.stdout.buffer.write(header)

def encrypt_files():
	encrypter = FileEncrypter(sys.stdout.buffer, key, iv)
	tar = tarfile.open(mode="w|", fileobj=encrypter, encoding="utf-8",
		format=tarfile.GNU_FORMAT, bufsize=20*512)
	while 1:
		path = paths_to_write.get()
		if not path:
			break
		tar.add(path, recursive=False)
	tar.close()
	if args.fill:
		try:
			while 1:
				encrypter.write(b"\0")
		except:
			pass

encrypt_thread = Thread(target=encrypt_files)
encrypt_thread.start()

i = 0
halt = False
while 1:
	path = files_in.readline()
	if not path:
		break
	path = path.rstrip("\n")
	if not path:
		continue
	try:
		f = calculate_tar_file_size(path)
	except Exception as e:
		files_out.write(f[0])
		print(e, file=sys.stderr)
		continue
	
	if i > 10 and args.no_underrun:
		halt = paths_to_write.empty()
	
	if(halt or (max_tar_size and
			calculate_tar_size(files_size + f[1]) > max_tar_size)):
		files_out.write(f[0] + "\n")
	else:
		paths_to_write.put(f[0])
		files_size += f[1]
	
	if halt:
		break
	i += 1

paths_to_write.put(None)

while 1:
	line = files_in.readline()
	if not line:
		break
	files_out.write(line)

files_out.close()
files_in.close()
total_size = header_size + calculate_tar_size(files_size)
print("Output: {} bytes".format(total_size), file=sys.stderr)

encrypt_thread.join()
