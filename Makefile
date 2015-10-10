all: vpcrypt.c
	gcc -Wall vpcrypt.c -lsodium -o vpcrypt
