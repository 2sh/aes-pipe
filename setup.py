#!/usr/bin/env python3

import setuptools

with open("README.md", "r") as f:
	long_description = f.read()

setuptools.setup(
	name="aes-pipe",
	version="1.0.3",
	
	author="2sh",
	author_email="contact@2sh.me",
	
	description="Encrypting piped data with AES",
	long_description=long_description,
	long_description_content_type="text/markdown",
	
	url="https://github.com/2sh/aes-pipe",
	
	packages=["aes_pipe"],
	
	install_requires=["pycrypto"],
	python_requires='>=3.4',
	classifiers=(
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
		"Operating System :: OS Independent",
		"Topic :: Security :: Cryptography"
	),
	
	entry_points={"console_scripts":["aes-pipe=aes_pipe:_main"]}
)
