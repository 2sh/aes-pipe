#!/usr/bin/env python3
#
#	Decrypter
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

import sys
import argparse

import tarfile

import hashlib
from Crypto.Cipher import AES

from io import BufferedWriter, BytesIO
import shlex
from subprocess import Popen, PIPE
from getpass import getpass

class Decrypter:
	def __init__(self, key, iv, in_fd):
		self.in_fd = in_fd
		self.decrypter = AES.new(key, AES.MODE_CBC, iv)

	def read(self, bufsize=20*512):
		data = self.in_fd.read(bufsize)
		if data:
			return self.decrypter.decrypt(data)
		else:
			return data

parser = argparse.ArgumentParser(description="Decrypter")
parser.add_argument("-e",
	dest="encoding",
	metavar="ENCODING",
	help="The TAR encoding to use. Default is 'utf-8'.")

parser.add_argument("-i",
	dest="input_source",
	metavar="SOURCE",
	help="Input source of encrypted data. Default is to input from STDIN.")
parser.add_argument("-o",
	dest="output_destination",
	metavar="DEST_PATH",
	help="Output destination for decrypted data. Default is to output a TAR file to STDOUT.")

parser.add_argument("-k",
	dest="key_command",
	metavar="COMMAND",
	help="The command to retrieve the encryption key, e.g. gpg. Default is to prompt for a passphrase.")
	
parser.add_argument("-p",
	dest="pass_header",
	action='store_true',
	help="Set to pass header to key command")
args = parser.parse_args()

if args.encoding:
	encoding = args.encoding
else:
	encoding = "utf-8"

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
	sp = Popen(shlex.split(args.key_command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
	data, err = sp.communicate(input=header_content)
	if sp.returncode != 0:
		print(err.decode(encoding='UTF-8'), file=sys.stderr)
		exit()
	iv = data[:AES.block_size]
	key = data[AES.block_size:]
else:
	key = hashlib.sha256(getpass("Enter a passphrase: ").encode('utf-8')).digest()
	iv = data_in.read(AES.block_size)

decrypter = Decrypter(key, iv, data_in)

if args.output_destination:
	tar = tarfile.open(mode="r|", fileobj=decrypter, encoding=encoding, format=tarfile.GNU_FORMAT, bufsize=20*512)
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
