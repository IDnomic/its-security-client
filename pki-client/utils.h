#pragma once

#include <openssl/ec.h>

#define TAIUTC 4
#define TAIUTCstr "4"

/* ETSI TS 103097 PARAMETERS */
#define TAGLEN 16
#define KEYLEN 16
#define NONCELEN 12

#define LOGINDENT(a) ((a>0)?(a-1):0)
#define NEXTLOGLEVEL(a) ((a>0)?(a+1):0)

#define LOGMSG(level, msg, ...) do { \
    fprintf(stderr, "%*.0i", level, 0); \
    fprintf(stderr, msg, ## __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0)

typedef struct {
    unsigned char *data;
    int datalen;
} databuf;


void unhex(char *src, unsigned char *dst, int *dstlen);
int hextobin(char *src, unsigned char **dst, int *dstlen);
int encodeasIntX(int i, unsigned char **dst, int *dstlen);
void dump(unsigned char *data, int len);
int readfile(char *filename, databuf **filecontent);
int writefile(char *filename, databuf *filecontent);
int pushbuf(databuf *buf, unsigned char *data, unsigned int len);
EC_KEY *readECPrivateKey(char *filename);
int writeECPrivateKey(char *filename, EC_KEY *key);
EC_KEY *readECPublicKey(char *filename);
int encryptccm(databuf *plaintext,
               unsigned char *key, unsigned char *nonce,
               databuf **ciphertext);
int decryptccm(databuf *ciphertext,
               unsigned char *key, unsigned char *nonce,
               databuf **plaintext);
void *ETSI_ECIES_KDF(const void *in, size_t inlen, void *out, size_t *outlen);
unsigned char *hashthis(unsigned char *data, int len, const EVP_MD *md);
unsigned char *getHashedId8(unsigned char *data, int len);

