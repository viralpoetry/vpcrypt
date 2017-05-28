VPcrypt
============

VPcrypt is a file encryption utility that runs from the Linux command prompt to provide a simple tool for encrypting files using a XSalsa20 stream cipher. VPcrypt is using hmacsha256 for integrity check, pbkdf for strong key derivations and finally XSalsa20 stream cipher for file confidentiality.

## Installation

You need [Sodium crypto library installed](https://github.com/jedisct1/libsodium).
```
$ sudo apt-get update
$ sudo apt-get install build-essential

# download libsodium
https://download.libsodium.org/libsodium/releases/

# extract libsodium
$ tar -xvzf LATEST.tar.gz

# install libsodium
$ ./configure
$ make
$ make check
$ sudo make install

# create the necessary links
$ sudo ldconfig

# Download this repository, then just build vpcrypt.c using make command:
$ make
```

## Usage

```./vpcrypt [ -e | --encrypt | -d | --decrypt] <file_name>```

I need peer review of this code! Browse through it before blindly using. Thank you.
