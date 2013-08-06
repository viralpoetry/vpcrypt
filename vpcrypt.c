
// Working under Sodium version 0.3
// gcc -Wall vpcrypt.c -lsodium -o vpcrypt
// Usage: ./vpcrypt [ -e | --encrypt | -d | --decrypt] <file_name>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <getopt.h>
#include <termios.h>
#include <sys/stat.h>

#define PBKDF_ITER 2000
//#define BLOCK_BYTES 1048576
#define BLOCK_BYTES 4096
#define SALT_BYTES 32
#define MIN(a,b) (((a)<(b))?(a):(b))
#define concateLen (crypto_stream_xsalsa20_NONCEBYTES + crypto_stream_xsalsa20_KEYBYTES)

void verifyCrypto( void );
ssize_t my_getpass (char **, size_t *, FILE *);
int pbkdf(const unsigned char *, const unsigned char *, size_t ,
          unsigned char *, size_t , unsigned int );
int encrypt_file(FILE *, FILE *, size_t , const unsigned char [], size_t);
int decrypt_file(FILE *, FILE *, size_t , const unsigned char [], size_t);

/* File header */
typedef struct {
    char magic[8];
    unsigned char salt[SALT_BYTES];
    unsigned char headerNonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char messageNonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char messageKey[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char headerMac[crypto_auth_hmacsha256_BYTES];
    size_t fileSize;
} FILE_HEADER;

/**
 * @brief encrypt, or decrypt options using getopt_long
 */
int main( int argc, char* argv[] ) {

    FILE *in, *out;
    size_t len = 0;
    ssize_t read;
    size_t fileSize;
    struct stat st;
    char *outName;
    char *pass = NULL;
    char *passReentered = NULL;

    //printf("Sodium version string: %s\n", sodium_version_string() );
    verifyCrypto( );

    int c;
    //int digit_optind = 0;

    while (1) {
        //int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"encrypt",     required_argument, 0,  'e' },
            {"decrypt",     required_argument, 0,  'd' },
            {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "e:d:", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
              printf("option %s", long_options[option_index].name);
              if (optarg) {
                  printf(" with arg %s", optarg);
              }
              printf("\n");
              break;

            /* Encrypt case */
            case 'e':
              in = fopen(optarg, "rb");
              if (in == NULL) {
                  fprintf(stderr, "error[-e]: Couldn't open file %s!\n", optarg);
                  return EXIT_FAILURE;
              }

              if ((outName = malloc(strlen(optarg) + 9)) == NULL) {
                  fprintf( stderr, "error: malloc!\n");
                  fclose(in);
                  return EXIT_FAILURE;
              }
              /* File size */
              stat(optarg, &st);
              fileSize = st.st_size;
              rewind(in);

              /* Create the name for encrypted file */
              strncpy(outName, optarg, strlen(optarg));
              strncpy(outName + strlen(optarg), ".crypted", 8);
              outName[strlen(optarg) + 8] = '\0';

              out = fopen(outName, "wb");
              if (out == NULL) {
                  fprintf(stderr, "error[-e]: Couldn't open file %s!\n", outName);
                  fclose(in);
                  free(outName);
                  return EXIT_FAILURE;
              }

              fprintf(stdout, "Enter password: \n");
              if( ( read = my_getpass (&pass, &len, stdin) ) != -1 ) {
                  if( read < 8 ) {
                      fprintf(stderr, "Password must be at least 8 characters long!\n");
                      free(pass);
                      free(outName);
                      fclose(in);
                      fclose(out);
                      return EXIT_FAILURE;
                  }

                  fprintf(stdout, "\nReenter password: \n");
                  if( ( read = my_getpass (&passReentered, &len, stdin) ) != -1 ) {
                      if(memcmp(pass, passReentered, MIN(strlen((char*)pass), strlen((char*)passReentered))) != 0 ) {
                          fprintf(stderr, "error: password did not match!\n");
                          free(pass);
                          free(outName);
                          free(passReentered);
                          fclose(in);
                          fclose(out);
                          return EXIT_FAILURE;
                      }

                      /* Pass with \0 */
                      encrypt_file(in, out, fileSize, (unsigned char*)pass, read);
                  }
              }

              /* MEMSET here... */
              free(pass);
              free(outName);
              free(passReentered);
              fclose(in);
              fclose(out);
              break;

            /* Decrypt case */
            case 'd':
              in = fopen(optarg, "rb");
              if (in == NULL) {
                  fprintf(stderr, "error[-d]: Couldn't open file %s!\n", optarg);
                  return EXIT_FAILURE;
              }

              /* File size */
              stat(optarg, &st);
              fileSize = st.st_size;
              rewind(in);

              /* Reconstruct file name */
              if( memcmp(".crypted", optarg + (strlen(optarg) - 8), 8) == 0 ) {
                  if ((outName = malloc(strlen(optarg) - 7)) == NULL) {
                      fprintf( stderr, "error: malloc!\n");
                      fclose(in);
                      return EXIT_FAILURE;
                  }
                  strncpy(outName, optarg, strlen(optarg) - 8);
                  outName[strlen(optarg) - 8] = '\0';
                  //fprintf(stdout, "filename %s\n", outName);
              } else {
                  if ((outName = malloc(strlen(optarg) + 8)) == NULL) {
                      fprintf( stderr, "error: malloc!\n");
                      fclose(in);
                      return EXIT_FAILURE;
                  }
                  strncpy(outName, optarg, strlen(optarg));
                  strncpy(outName + strlen(optarg), "(plain)", 7);
                  outName[strlen(optarg) + 7] = '\0';
                  fprintf(stdout, "filename %s\n", outName);
              }

              out = fopen(outName, "wb");
              if (out == NULL) {
                  fprintf(stderr, "error[-d]: Couldn't open file %s!\n", outName);
                  free(outName);
                  fclose(in);
                  return EXIT_FAILURE;
              }

              fprintf(stdout, "Enter password: \n");
              if( ( read = my_getpass (&pass, &len, stdin) ) != -1 ) {
                  decrypt_file(in, out, fileSize, (unsigned char*)pass, read);
              }

              free(pass);
              free(outName);
              fclose(in);
              fclose(out);
              break;

            case '?':
              break;

            default:
              printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        /*while (optind < argc) {
            printf("%s ", argv[optind++]);
        }*/
        fprintf(stderr, "Unrecognized command!\nUsage:  [ -e | --encrypt | -d | --decrypt] <file_name>\n\n");
    }

    //memset(weakPass, 0, strlen((char*)weakPass));
    return EXIT_SUCCESS;
}

/**
 * @brief Get password without echoing it
 * http://www.gnu.org/software/libc/manual/html_node/getpass.html
 */
ssize_t my_getpass (char **lineptr, size_t *n, FILE *stream) {
    struct termios old, new;
    int nread;

    /* Turn echoing off and fail if we can't. */
    if (tcgetattr (fileno (stream), &old) != 0) {
      return -1;
    }
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0) {
      return -1;
    }

    /* Read the password. */
    nread = getline (lineptr, n, stream);

    /* Restore terminal. */
    (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);

    return nread;
}

/**
 * @brief testing crypto parts
 */
void verifyCrypto( void ) {

    int result;
    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    unsigned char key[32] = "Jefe";
    unsigned char message[] = "what do ya want for nothing?";
    unsigned char expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    unsigned char k[crypto_stream_xsalsa20_KEYBYTES] = {
        0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d,
        0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25, 0x25,
        0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d,
        0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80, 0x30
    };
    unsigned char iv[crypto_stream_xsalsa20_NONCEBYTES] = {
        0x9e, 0x64, 0x5a, 0x74, 0xe9, 0xe0, 0xa6, 0x0d,
        0x82, 0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5, 0x1a,
        0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70, 0x0c
    };

    unsigned char pt[32] = {
        0x09, 0x3c, 0x5e, 0x55, 0x85, 0x57, 0x96, 0x25,
        0x33, 0x7b, 0xd3, 0xab, 0x61, 0x9d, 0x61, 0x57,
        0x60, 0xd8, 0xc5, 0xb2, 0x24, 0xa8, 0x5b, 0x1d,
        0x0e, 0xfe, 0x0e, 0xb8, 0xa7, 0xee, 0x16, 0x3a
    };

    unsigned char ct[32];

    unsigned char verify[32] = {
        0xb2, 0xaf, 0x68, 0x8e, 0x7d, 0x8f, 0xc4, 0xb5,
        0x08, 0xc0, 0x5c, 0xc3, 0x9d, 0xd5, 0x83, 0xd6,
        0x71, 0x43, 0x22, 0xc6, 0x4d, 0x7f, 0x3e, 0x63,
        0x14, 0x7a, 0xed, 0xe2, 0xd9, 0x53, 0x49, 0x34
    };

    /* Verify hmacsha256
       "Test Case 2" from RFC 4231
       http://tools.ietf.org/html/rfc4231
    */
    crypto_auth_hmacsha256(mac, message, sizeof message - 1U, key);
    result = memcmp( mac, expected, crypto_auth_hmacsha256_BYTES);
    if( result != 0 ) {
        fprintf( stderr, "error: verifyCrypto failed to verify hmacsha256!\n %d", result);
        exit( EXIT_FAILURE );
    }

    /* Verify xsalsa20 stream
       Test Case 1
       https://tahoe-lafs.org/trac/pycryptopp/attachment/ticket/40/testx1.txt
    */
    crypto_stream_xsalsa20_xor(ct, pt, 32, iv, k);
    result = memcmp( ct, verify, 30 );
    if( result != 0 ) {
        fprintf( stderr, "error: verifyCrypto failed to verify xsalsa20 stream! %d\n", result);
        exit( EXIT_FAILURE );
    }

    /* Verify random number generator (weak test...) */
    int i;
    unsigned char x[65536];
    unsigned long long freq[256];

    randombytes(x,sizeof x);
    for (i = 0;i < 256;++i) { freq[i] = 0; }
    for (i = 0;i < sizeof x;++i) { ++freq[255 & (int) x[i]]; }
    for (i = 0;i < 256;++i) {
        if (!freq[i]) {
            fprintf( stderr, "error: randombytes looks nonrandom!\n");
            exit( EXIT_FAILURE );
        }
    }
}

/**
 * @brief Key derivation function using crypto_auth_hmacsha256
 * based on OpenBSD's src/sbin/bioctl/pbkdf2.c
 */
int pbkdf(const unsigned char *pass, const unsigned char *salt, size_t salt_len,
    unsigned char *key, size_t key_len, unsigned int rounds) {

    size_t r;
    unsigned int i, j;
    unsigned int count;
    unsigned char *asalt;
    unsigned char d1[crypto_auth_hmacsha256_BYTES];
    unsigned char d2[crypto_auth_hmacsha256_BYTES];
    unsigned char obuf[crypto_auth_hmacsha256_BYTES];

    if (rounds < 1 || key_len == 0) {
        return -1;
    }
    if (salt_len == 0 || salt_len > SIZE_MAX - 4) {
        return -1;
    }
    if ((asalt = malloc(salt_len + 4)) == NULL) {
        return -1;
    }

    memcpy(asalt, salt, salt_len);

    for (count = 1; key_len > 0; count++) {
        asalt[salt_len + 0] = (count >> 24) & 0xff;
        asalt[salt_len + 1] = (count >> 16) & 0xff;
        asalt[salt_len + 2] = (count >> 8) & 0xff;
        asalt[salt_len + 3] = count & 0xff;
        //hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
        crypto_auth_hmacsha256(d1, asalt, salt_len + 4, pass);
        memcpy(obuf, d1, sizeof(obuf));

        for (i = 1; i < rounds; i++) {

            //hmac_sha1(d1, sizeof(d1), pass, pass_len, d2);
            crypto_auth_hmacsha256(d2, d1, 32, pass);
            memcpy(d1, d2, 32);
            for (j = 0; j < 32; j++)
                obuf[j] ^= d1[j];
        }

        r = MIN(key_len, 32);
        memcpy(key, obuf, r);
        key += r;
        key_len -= r;
    };

    memset(asalt, 0, salt_len + 4);
    free(asalt);
    memset(d1, 0, sizeof(d1));
    memset(d2, 0, sizeof(d2));
    memset(obuf, 0, sizeof(obuf));

    return 0;
}

/**
 * @brief Encryption function
 *
 * @param fIn  input  file  (plaintext)
 * @param fOut output file (ciphertext)
 * @param fileSize file size
 * @param weakKey user submitted passphrase
 * @param weakKeyLen length of passphrase
 */
int encrypt_file(FILE *fIn, FILE *fOut, size_t fileSize, const unsigned char weakKey[], size_t weakKeyLen) {
    void *addr;
    int err = 0;
    int lastBlockLen = 0;
    FILE_HEADER fHeader;
    unsigned int counter = 0;
    unsigned char pt[BLOCK_BYTES];
    unsigned char nonceKey[concateLen];
    unsigned char passHash[crypto_hash_sha256_BYTES];
    unsigned char key[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char headerKey[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char ct[BLOCK_BYTES + crypto_auth_hmacsha256_BYTES];
    /* Same array for simplicity */
    unsigned char *mac = ct + BLOCK_BYTES;

    /* Generate one time password and nonce for the file */
    randombytes_stir();
    randombytes(fHeader.salt, SALT_BYTES);
    randombytes(key, crypto_stream_xsalsa20_KEYBYTES);
    randombytes(nonce, crypto_stream_xsalsa20_NONCEBYTES);
    randombytes(fHeader.headerNonce, crypto_stream_xsalsa20_NONCEBYTES);
    randombytes_close();
    /* Last 4 bytes for counter */
    memset(nonce + crypto_stream_xsalsa20_NONCEBYTES - 4, 0, 4);

    /* Magic value */
    strncpy(fHeader.magic, "VPcrypt", 8);
    err = fwrite(&fHeader.magic, 8,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write magic!\n");
        exit( EXIT_FAILURE );
    }

    /* Salt for password derivation  */
    err = fwrite(&fHeader.salt, SALT_BYTES,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write headerNonce!\n");
        exit( EXIT_FAILURE );
    }

    /* Generate hash for pbkdf */
    crypto_hash_sha256(passHash, weakKey, weakKeyLen - 1);

    /* Generate cryptographically strong key */
    if(pbkdf(passHash, fHeader.salt, SALT_BYTES, headerKey, crypto_stream_xsalsa20_KEYBYTES, PBKDF_ITER) != 0) {
        fprintf( stderr, "error: pbkdf2!\n");
        exit( EXIT_FAILURE );
    }

    /* Nonce for encrypted header (nonce & pass for file)  */
    err = fwrite(&fHeader.headerNonce, crypto_stream_xsalsa20_NONCEBYTES,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write headerNonce!\n");
        exit( EXIT_FAILURE );
    }

    /* Encrypt nonce for file */
    crypto_stream_xsalsa20_xor(fHeader.messageNonce, nonce, crypto_stream_xsalsa20_NONCEBYTES, fHeader.headerNonce, headerKey);
    err = fwrite(&fHeader.messageNonce, crypto_stream_xsalsa20_NONCEBYTES,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write messageNonce!\n");
        exit( EXIT_FAILURE );
    }

    /* Increment nonce value */
    fHeader.headerNonce[crypto_stream_xsalsa20_NONCEBYTES - 1] ^= 1;
    /* Encrypted key for file */
    crypto_stream_xsalsa20_xor(fHeader.messageKey, key, crypto_stream_xsalsa20_KEYBYTES, fHeader.headerNonce, headerKey);
    err = fwrite(&fHeader.messageKey, crypto_stream_xsalsa20_KEYBYTES,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write messageKey!\n");
        exit( EXIT_FAILURE );
    }

    /* Authentication code for encrypted nonce and key to verify correctness */
    addr = memcpy(nonceKey, fHeader.messageNonce, crypto_stream_xsalsa20_NONCEBYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }
    addr = memcpy(nonceKey + crypto_stream_xsalsa20_NONCEBYTES, fHeader.messageKey, crypto_stream_xsalsa20_KEYBYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }
    crypto_auth_hmacsha256(fHeader.headerMac, nonceKey, concateLen - 1, headerKey);
    err = fwrite(&fHeader.headerMac, crypto_auth_hmacsha256_BYTES,  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write hmac!\n");
        exit( EXIT_FAILURE );
    }

    /* File size before encryption */
    err = fwrite(&fileSize, sizeof(size_t),  1, fOut);
    if( err != 1 ) {
        fprintf( stderr, "error: Write fileSize!\n");
        exit( EXIT_FAILURE );
    }

    /* The key is IV for hmac chaining simultaneously */
    addr = memcpy(mac, key, crypto_auth_hmacsha256_BYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }

    /* Full blocks encryption */
    while ( ( lastBlockLen = fread( pt, sizeof(char), BLOCK_BYTES, fIn ) ) == BLOCK_BYTES ) {

        crypto_stream_xsalsa20_xor(ct, pt, BLOCK_BYTES, nonce, key);

        err = fwrite(ct, sizeof(char), BLOCK_BYTES, fOut);
        if( err != BLOCK_BYTES ) {
            fprintf( stderr, "error: Write block!\n");
            exit( EXIT_FAILURE );
        }

        /* Chaining hmac with previous one */
        crypto_auth_hmacsha256(mac, ct, sizeof ct - 1U, key);
        //crypto_auth_hmacsha256(mac, ct, sizeof ct, key);

        /* Increment counter value */
        counter++;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 4] = (counter >> 24) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 3] = (counter >> 16) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 2] = (counter >> 8) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 1] = counter & 0xff;
    }

    /* Last block encryption */
    if( lastBlockLen > 0 ) {
        fread(pt, sizeof(char), lastBlockLen, fIn);
        crypto_stream_xsalsa20_xor(ct, pt, lastBlockLen, nonce, key);
        err = fwrite(ct, sizeof(char), lastBlockLen, fOut);
        if( err != lastBlockLen ) {
            fprintf( stderr, "error: Write last block!\n");
            exit( EXIT_FAILURE );
        }

        addr = memcpy(ct + lastBlockLen, mac, crypto_auth_hmacsha256_BYTES);
        if( addr == NULL ) {
            fprintf( stderr, "error: memcpy!\n");
            exit( EXIT_FAILURE );
        }

        /* Compute last hmac value */
        crypto_auth_hmacsha256(mac, ct, lastBlockLen + crypto_auth_hmacsha256_BYTES - 1U, key);

    }

    /* Append last hmac at the end of file */
    err = fwrite(mac, sizeof(char), crypto_auth_hmacsha256_BYTES, fOut);
    if( err != crypto_auth_hmacsha256_BYTES ) {
        fprintf( stderr, "error: Write mac!\n");
        exit( EXIT_FAILURE );
    }

    memset(key, 0, crypto_stream_xsalsa20_KEYBYTES);
    memset(headerKey, 0, crypto_stream_xsalsa20_KEYBYTES);
    memset(passHash, 0, crypto_hash_sha256_BYTES);

    return 0;
}

/**
 * @brief Decryption function
 *
 * @param fIn  input  file  (plaintext)
 * @param fOut output file (ciphertext)
 * @param fileSize file size
 * @param weakKey user submitted passphrase
 * @param weakKeyLen length of passphrase
 */

int decrypt_file(FILE *fIn, FILE *fOut, size_t fileSize, const unsigned char weakKey[], size_t weakKeyLen) {
    void *addr;
    int err = 0;
    size_t blocks;
    size_t lastBlockLen;
    FILE_HEADER fHeader;
    unsigned int counter = 0;
    unsigned char pt[BLOCK_BYTES];
    unsigned char nonceKey[concateLen];
    unsigned char passHash[crypto_hash_sha256_BYTES];
    unsigned char key[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char expectedMac[crypto_auth_hmacsha256_BYTES];
    unsigned char headerKey[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char ct[BLOCK_BYTES + crypto_auth_hmacsha256_BYTES];
    unsigned char *mac = ct + BLOCK_BYTES;

    /* Compare magic value */
    err = fread(&fHeader.magic, 8,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Write magic!\n");
        exit( EXIT_FAILURE );
    } else {
        err = memcmp(fHeader.magic, "VPcrypt", 8);
        if(err != 0) {
            fprintf(stderr, "error: Invalid VPcrypt file!\n");
            exit( EXIT_FAILURE );
        }
    }

    /* Read salt from file */
    err = fread(&fHeader.salt, SALT_BYTES,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Read salt!\n");
        exit( EXIT_FAILURE );
    }

    /* Generate hash for pbkdf */
    crypto_hash_sha256(passHash, weakKey, weakKeyLen - 1);

    /* Generate key from salt and user input */
    if(pbkdf(passHash, fHeader.salt, SALT_BYTES, headerKey, crypto_stream_xsalsa20_KEYBYTES, PBKDF_ITER) != 0) {
        fprintf( stderr, "error: pbkdf2!\n");
        exit( EXIT_FAILURE );
    }

    /* Read nonce for encrypted header (nonce & pass for file)  */
    err = fread(&fHeader.headerNonce, crypto_stream_xsalsa20_NONCEBYTES,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Read headerNonce!\n");
        exit( EXIT_FAILURE );
    }

    /* Read encrypted nonce for current file */
    err = fread(&fHeader.messageNonce, crypto_stream_xsalsa20_NONCEBYTES,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Read messageNonce!\n");
        exit( EXIT_FAILURE );
    }

    /* Read encrypted key for current file */
    err = fread(&fHeader.messageKey, crypto_stream_xsalsa20_KEYBYTES,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Read messageKey!\n");
        exit( EXIT_FAILURE );
    }

    /* compute hmac for encrypted nonce and key */
    addr = memcpy(nonceKey, fHeader.messageNonce, crypto_stream_xsalsa20_NONCEBYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }
    addr = memcpy(nonceKey + crypto_stream_xsalsa20_NONCEBYTES, fHeader.messageKey, crypto_stream_xsalsa20_KEYBYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }
    /* Read hmac for header from file */
    err = fread(&fHeader.headerMac, crypto_auth_hmacsha256_BYTES,  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: read headerMac!\n");
        exit( EXIT_FAILURE );
    }

    /* Compare hmac values */
    if( crypto_auth_hmacsha256_verify(fHeader.headerMac, nonceKey, concateLen - 1, headerKey) == -1 ) {
        fprintf(stderr, "error: Wrong password!\n");
        exit( EXIT_FAILURE );
    }

    /* Read size of file before encryption */
    err = fread(&fHeader.fileSize, sizeof(size_t),  1, fIn);
    if( err != 1 ) {
        fprintf( stderr, "error: Read fileSize!\n");
        exit( EXIT_FAILURE );
    }

    /* Comparison with expected file size */
    if( fileSize != (fHeader.fileSize + sizeof(fHeader) + crypto_auth_hmacsha256_BYTES) ) {
        fprintf( stderr, "error: File size did not match expected size!\n");
        exit( EXIT_FAILURE );
    }

    /* Decrypt nonce and key for current file */
    crypto_stream_xsalsa20_xor(nonce, fHeader.messageNonce, crypto_stream_xsalsa20_NONCEBYTES, fHeader.headerNonce, headerKey);
    /* Incrementing counter */
    fHeader.headerNonce[crypto_stream_xsalsa20_NONCEBYTES - 1] ^= 1;
    crypto_stream_xsalsa20_xor(key, fHeader.messageKey, crypto_stream_xsalsa20_KEYBYTES, fHeader.headerNonce, headerKey);

    /* The key is IV for hmac chaining simultaneously */
    addr = memcpy(mac, key, crypto_auth_hmacsha256_BYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }

    blocks = fHeader.fileSize / BLOCK_BYTES;
    lastBlockLen = fHeader.fileSize % BLOCK_BYTES;

    /* Full blocks decryption */
    while ( blocks > 0 ) {
        blocks--;
        err = fread( ct, sizeof(char), BLOCK_BYTES, fIn );
        if( err != BLOCK_BYTES ) {
            fprintf( stderr, "error: Read blocks!\n");
            exit( EXIT_FAILURE );
        }
        crypto_stream_xsalsa20_xor(pt, ct, BLOCK_BYTES, nonce, key);
        err = fwrite(pt, sizeof(char), BLOCK_BYTES, fOut);
        if( err != BLOCK_BYTES ) {
            fprintf( stderr, "error: Write blocks!\n");
            exit( EXIT_FAILURE );
        }

        /* Chaining hmac with previous one */
        crypto_auth_hmacsha256(mac, ct, sizeof ct - 1U, key);

        /* Increment counter value */
        counter++;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 4] = (counter >> 24) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 3] = (counter >> 16) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 2] = (counter >> 8) & 0xff;
        nonce[crypto_stream_xsalsa20_NONCEBYTES - 1] = counter & 0xff;
    }

    /* Last block decryption */
    err = fread(ct, sizeof(char), lastBlockLen, fIn);
    if( err != lastBlockLen ) {
        fprintf( stderr, "error: Read last block!\n");
        exit( EXIT_FAILURE );
    }
    crypto_stream_xsalsa20_xor(pt, ct, lastBlockLen, nonce, key);
    err = fwrite(pt, sizeof(char), lastBlockLen, fOut);
    if( err != lastBlockLen ) {
        fprintf( stderr, "error: Write last block!\n");
        exit( EXIT_FAILURE );
    }

    /* Append last hmac at the end of file */
    addr = memcpy(ct + lastBlockLen, mac, crypto_auth_hmacsha256_BYTES);
    if( addr == NULL ) {
        fprintf( stderr, "error: memcpy!\n");
        exit( EXIT_FAILURE );
    }

    /* Read hmac from the end of file */
    err = fread(expectedMac, sizeof(char), crypto_auth_hmacsha256_BYTES, fIn);
    if( err != crypto_auth_hmacsha256_BYTES ) {
        fprintf( stderr, "error: Read mac from file!\n");
        exit( EXIT_FAILURE );
    }

    /* Compute last hmac and compare with expected one */
    if( crypto_auth_hmacsha256_verify(expectedMac, ct, lastBlockLen + crypto_auth_hmacsha256_BYTES - 1U, key) == -1 ) {
        fprintf(stderr, "error: crypto_auth_verify!\n");
        exit( EXIT_FAILURE );
    }

    memset(key, 0, crypto_stream_xsalsa20_KEYBYTES);
    memset(passHash, 0, crypto_hash_sha256_BYTES);
    memset(headerKey, 0, crypto_stream_xsalsa20_KEYBYTES);

    return 0;
}
