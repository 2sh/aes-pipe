#!/usr/bin/env python3
#
#	SSFE
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

import tarfile
import math

from Crypto.Cipher import AES
from Crypto.Util import Counter


class FileEncrypter:
	def __init__(self, out_fd, key, iv):
		self.out_fd = out_fd
		ctr = Counter.new(64, prefix=iv)
		self.encrypter = AES.new(key, AES.MODE_CTR, counter=ctr)

	def write(self, data):
		self.out_fd.write(self.encrypter.encrypt(data))

class FileDecrypter:
	def __init__(self, in_fd, key, iv):
		self.in_fd = in_fd
		
		ctr = Counter.new(64, prefix=iv)
		self.cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

	def read(self, bufsize=20*512):
		data = self.in_fd.read(bufsize)
		if data:
			return self.cipher.decrypt(data)
		else:
			return data

def determine_tar_file_size(path):
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
		return size
	else:
		# only the 512 byte header
		size += 512
		return size

def determine_tar_size(data_size, blocking_factor=20):
	# End of archive marked by two consecutive zero-filled records
	return int((blocking_factor*512) *
		math.ceil((data_size + 512*2)/(blocking_factor*512)))

def _file_iter_lines_gen(input_file, delimiter, size):
	partial_line = ""
	while True:
		chars = input_file.read(size)
		if not chars:
			break
		partial_line += chars
		lines = partial_line.split(delimiter)
		partial_line = lines.pop()
		for line in lines:
			yield line + delimiter
	if partial_line:
		yield partial_line

def _file_iter_lines(input_file, delimiter="\n", size=8192):
	if delimiter == "\n":
		return input_file
	else:
		return _file_iter_lines_gen(input_file, delimiter, size)

class _FilelistOutFile:
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

_unit_prefixes = {
	"k": 1,
	"m": 2,
	"g": 3,
	"t": 4,
	"p": 5,
	"e": 6,
	"z": 7,
	"y": 8,
}

def _storage_size(value):
	value = value.lower()
	if not value:
		raise Exception("Size not given.")
	if value[-1] == "i":
		if value[-2:-1] in _unit_prefixes:
			return int(float(value[:-2]) * 2**(_unit_prefixes[value[-2]]*10))
		else:
			raise Exception("Invalid binary prefix.")
	elif value[-1] in _unit_prefixes:
		return int(float(value[:-1]) * 1000**_unit_prefixes[value[-1]])
	else:
		return int(value)

def _convert_passphrase_to_key(passphrase, salt, length):
	return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
		salt, 1000000, length)

def _encrypt(args):
	from Crypto.Random import get_random_bytes

	from queue import Queue
	from threading import Thread
	
	if args.filelist == "-":
		filelist_source = sys.stdin.fileno()
	else:
		filelist_source = args.filelist

	if args.null_delimiter:
		delimiter = "\0"
	else:
		delimiter = "\n"

	iv = get_random_bytes(8)

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
		key = _convert_passphrase_to_key(
			passphrase, iv, args.key_size)

	header += iv
	header_size = len(header)

	if args.size:
		max_tar_size = args.size-header_size
	else:
		max_tar_size = None

	paths_to_write = Queue()

	files_in = open(filelist_source, "r")
	files_in_reader = _file_iter_lines(files_in, delimiter)
	files_out = _FilelistOutFile(args.filelist_out)

	sys.stdout.buffer.write(header)

	def _encrypt_files():
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

	encrypt_thread = Thread(target=_encrypt_files)
	encrypt_thread.start()

	i = 0
	files_size = 0
	halt = False
	while 1:
		path = next(files_in_reader, None)
		if not path:
			break
		path = path.rstrip(delimiter)
		if not path:
			continue
		try:
			file_size = determine_tar_file_size(path)
		except Exception as e:
			files_out.write(path + delimiter)
			print(e, file=sys.stderr)
			continue
		
		if i > 10 and args.no_underrun:
			halt = paths_to_write.empty()
		
		if(halt or (max_tar_size and
				determine_tar_size(files_size + file_size) > max_tar_size)):
			files_out.write(path + delimiter)
		else:
			paths_to_write.put(path)
			files_size += file_size
		
		if halt:
			break
		i += 1

	paths_to_write.put(None)

	while 1:
		line = next(files_in_reader, None)
		if not line:
			break
		files_out.write(line)

	files_out.close()
	files_in.close()
	total_size = header_size + determine_tar_size(files_size)
	print("Output: {} bytes".format(total_size), file=sys.stderr)

	encrypt_thread.join()

def _decrypt(args):
	if args.input_source:
		data_in = open(args.input_source, "rb")
	else:
		data_in = sys.stdin.buffer

	if args.key_command:
		if args.pass_header:
			length = int.from_bytes(data_in.read(8), "big")
			header_content = data_in.read(length)
		else:
			header_content = None
		sp = Popen(args.key_command, shell=True,
			stdin=PIPE, stdout=PIPE, stderr=PIPE)
		key, err = sp.communicate(input=header_content)
		if sp.returncode != 0:
			print(err.decode(encoding='UTF-8'), file=sys.stderr)
			exit()

	iv = data_in.read(8)

	if not args.key_command:
		key = _convert_passphrase_to_key(
			getpass("Enter a passphrase: "), iv, args.key_size)

	decrypter = FileDecrypter(data_in, key, iv)

	if args.output_destination:
		tar = tarfile.open(mode="r|", fileobj=decrypter, encoding="utf-8",
			format=tarfile.GNU_FORMAT, bufsize=20*512)
		tar.extractall(args.output_destination)
	else:
		while True:
			data = decrypter.read()
			if not data:
				break
			sys.stdout.buffer.write(data)

	if args.input_source:
		data_in.close()
	if args.output_destination:
		tar.close()


if __name__ == "__main__":
	import argparse
	
	from subprocess import Popen, PIPE
	from getpass import getpass
	
	import hashlib
	
	parser = argparse.ArgumentParser(description="SSFE")
	subparsers = parser.add_subparsers(dest="mode", help="mode")
	subparsers.required=True
	
	
	parser_encrypt = subparsers.add_parser("encrypt")
	
	parser_encrypt.add_argument("filelist",
		help="A list of all the individual files and folders to be encrypted.")
	parser_encrypt.add_argument("-l",
		dest="filelist_out",
		metavar="PATH",
		help="File to which to write list of files that did not "
			"fit within the size limit or failed.")
	parser_encrypt.add_argument("-s",
		dest="size",
		type=_storage_size,
		help="The size of the destination storage.")
	parser_encrypt.add_argument("-u",
		dest="no_underrun",
		action="store_true",
		help="Attempt to prevent a buffer underrun. If the buffer is empty, "
			"the output is halted and the paths of any remaining files "
			"are written to the out file list.")
	parser_encrypt.add_argument("-f",
		dest="fill",
		action="store_true",
		help="Fill any remaining space on the destination storage "
			"with random bytes.")
	parser_encrypt.add_argument("-c",
		dest="key_command",
		metavar="COMMAND",
		help="Generates a 32-byte encryption key and pipes it into "
			"the specified command, e.g. gpg or dd. Otherwise, "
			"a passphrase is requested through a prompt.")
	parser_encrypt.add_argument("-k",
		dest="key_size",
		metavar="SIZE",
		type=lambda x: int(x)//8,
		default=32,
		help="The AES key size in bits: 128, 192 or 256 [Default: 256].")
	parser_encrypt.add_argument("-0",
		dest="null_delimiter",
		action="store_true",
		help="Read and write null (\\0) delimitered filelists.")
	
	
	parser_decrypt = subparsers.add_parser("decrypt")
	
	parser_decrypt.add_argument("-i",
		dest="input_source",
		metavar="SOURCE",
		help="Input source of encrypted data. Default is to input from STDIN.")
	parser_decrypt.add_argument("-o",
		dest="output_destination",
		metavar="DEST_PATH",
		help="Output destination of the decrypted files. "
			"Default is to output a UTF-8 encoded TAR file to STDOUT.")
	parser_decrypt.add_argument("-c",
		dest="key_command",
		metavar="COMMAND",
		help="The command to retrieve the encryption key, e.g. gpg. "
			"Default is to prompt for a passphrase.")
	parser_decrypt.add_argument("-k",
		dest="key_size",
		metavar="SIZE",
		type=lambda x: int(x)//8,
		default=32,
		help="The AES key size in bits: 128, 192 and 256 [Default: 256].")
	parser_decrypt.add_argument("-p",
		dest="pass_header",
		action='store_true',
		help="Set to pass header to key command")
	
	
	args = parser.parse_args()
	
	if args.mode == "encrypt":
		_encrypt(args)
	elif args.mode == "decrypt":
		_decrypt(args)
