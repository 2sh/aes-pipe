#!/usr/bin/env python3
#
#	aes-pipe - Encrypting piped data with AES
#
#	Copyright (C) 2018 2sh <contact@2sh.me>
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

from Crypto.Cipher import AES
from Crypto.Util import Counter

from hashlib import pbkdf2_hmac


class FileEncryption:
	def __init__(self, fd, mode, key, nonce):
		self.fd = fd
		self.mode = mode
		if self.mode == "CTR":
			ctr = Counter.new(128, initial_value=int.from_bytes(
				nonce[:AES.block_size], byteorder="big"))
			self.cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
		elif self.mode == "CBC":
			self.cipher = AES.new(key, AES.MODE_CBC, nonce[:AES.block_size])
	
	def write(self, data):
		try:
			self.fd.write(self.cipher.encrypt(data))
		except ValueError as e:
			block_remainder = len(data) % AES.block_size
			if block_remainder and args.mode == "CBC":
				data += b"\0" * (AES.block_size - block_remainder)
			else:
				raise e
			self.fd.write(self.cipher.encrypt(data))
	
	def read(self, bufsize=20*512):
		data = self.fd.read(bufsize)
		if data:
			return self.cipher.decrypt(data)
		else:
			return data

def _convert_passphrase_to_key(passphrase, salt, length):
	return pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
		salt, 1000000, length)

def _main():
	import argparse
	import sys
	
	import subprocess
	
	from getpass import getpass
	
	from Crypto.Random import get_random_bytes
	
	parser = argparse.ArgumentParser(
		description="The purpose of this program is simply to encrypt data "
			"with a determinable output data size. If the key command is "
			"specified, the output data size is the input data size. "
			"If not, the output data size is the input data size + AES key "
			"sized prepended nonce (16, 24 or 32 bytes).")
	parser.add_argument("-d", "--decrypt",
		dest="decrypt",
		action="store_true",
		help="Decrypt the input data. Default is to encrypt.")
	parser.add_argument("-m", "--mode",
		dest="mode",
		metavar="MODE",
		type=lambda x: x.upper(),
		default="CTR",
		help="The AES mode: CTR or CBC [Default: CTR]. The input data size "
			"in mode CBC needs to be a multiple of 16, otherwise NULLs are "
			"added for padding. Mode CTR does not have this issue. "
			"Data errors during decryption in mode CBC destroy "
			"all following data while they only affect the corrupt bits in "
			"mode CTR.")
	parser.add_argument("-s", "--key-size",
		dest="key_size",
		metavar="SIZE",
		type=int,
		default=32,
		help="The AES key size in bytes: 16, 24 or 32 [Default: 32]. "
		"This is also the size of the nonce.")
	parser.add_argument("-b", "--buffer-size",
		dest="buffer_size",
		metavar="SIZE",
		type=int,
		default=20*512,
		help="The input read buffer in bytes [Default: 20*512]")
	parser.add_argument("-k", "--key-command",
		dest="key_command",
		metavar="COMMAND",
		help="When encrypting, a generated encryption key and nonce are piped "
			"into the specified command, e.g. gpg. "
			"When decrypting, the output of the command is used as the "
			"key and nonce. "
			"If not specified, a passphrase is requested through a prompt and "
			"the nonce is prepended to the encrypted data.")
	
	args = parser.parse_args()
	
	if not args.decrypt:
		nonce = get_random_bytes(args.key_size)
		
		if args.key_command:
			key = get_random_bytes(args.key_size)
			sp = subprocess.Popen(args.key_command, shell=True,
				stdin=subprocess.PIPE, stdout=subprocess.STDERR)
			sp.communicate(key+nonce)
			if sp.returncode != 0:
				exit()
		else:
			while True:
				passphrase = getpass("Enter a passphrase: ")
				if passphrase == getpass("Enter the same passphrase again: "):
					break
				else:
					print("The passphrases did not match. Try again.",
						file=sys.stderr)
			key = _convert_passphrase_to_key(passphrase,
				nonce, args.key_size)
			sys.stdout.buffer.write(nonce)
		
		encryption = FileEncryption(sys.stdout.buffer, args.mode, key, nonce)
		while 1:
			data = sys.stdin.buffer.read(args.buffer_size)
			if not data:
				break
			encryption.write(data)
	else:
		if args.key_command:
			sp = subprocess.Popen(args.key_command, shell=True,
				stdout=subprocess.PIPE)
			data, _ = sp.communicate()
			if sp.returncode != 0:
				exit()
			key, nonce = data[:args.key_size], data[args.key_size:]
		else:
			nonce = sys.stdin.buffer.read(args.key_size)
			key = _convert_passphrase_to_key(getpass("Enter a passphrase: "),
				nonce, args.key_size)
		
		encryption = FileEncryption(sys.stdin.buffer, args.mode, key, nonce)
		
		while 1:
			data = encryption.read(args.buffer_size)
			if not data:
				break
			sys.stdout.buffer.write(data)

if __name__ == "__main__":
	_main()
