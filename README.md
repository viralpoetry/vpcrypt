VPcrypt
============

VPcrypt is a file encryption utility that runs from the Linux command prompt to provide a simple tool for encrypting files using a XSalsa20 stream cipher. VPcrypt is using hmacsha256 for integrity check, pbkdf for strong key derivations and finally XSalsa20 stream cipher for file confidentiality.

## Installation

You need [Sodium crypto library installed](https://github.com/jedisct1/libsodium).
Download vpcrypt.c file from this repository, then just build:

    gcc -Wall vpcrypt.c -lsodium -o sifrator

## Usage

    ./vpcrypt [ -e | --encrypt | -d | --decrypt] <file_name>

I need peer review of this code! Browse through it before blindly using. Thank you.

## TODO

Paranoia mode switch (encrypt file without identifiable header information).
Digital signatures.
