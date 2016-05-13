#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

void unhex(char *src, unsigned char *dst, int *dstlen)
{
  int i = 0;
  int srclen = 0;
  int maxdstlen = 0;
  unsigned char c1, c2, c;

  if (!dstlen)
    goto done;
  maxdstlen = *dstlen;

  if (!dst)
  {
    *dstlen = 0;
    goto done;
  }

  if (!src)
  {
    *dstlen = 0;
    goto done;
  }

  if ((srclen = strlen(src)) % 2)
  {
    *dstlen = 0;
    goto done;
  }

  if (srclen/2 > maxdstlen)
  {
    *dstlen = 0;
    goto done;
  }

  for(i = 0; i < srclen; i++)
  {
    c = src[i];
    if (!(    ((c >= '0') && (c <= '9'))
           || ((c >= 'A') && (c <= 'F'))
           || ((c >= 'a') && (c <= 'f'))
       ))
    {
      *dstlen = 0;
      goto done;
    }
  }

  for(i = 0; i < srclen; i+=2)
  {
    c1 = src[i];
    c2 = src[i+1];
    c =  ((c1>='a'?c1-'a'+10:(c1>='A'?c1-'A'+10:c1-'0')) <<4)
        + (c2>='a'?c2-'a'+10:(c2>='A'?c2-'A'+10:c2-'0'));
    dst[i/2] = c;
  }

  *dstlen = srclen/2;

done:
  return;
}


int hextobin(char *src, unsigned char **dst, int *dstlen)
{
  int result = 0;
  unsigned char *dummy = NULL;
  int len = 0,
      len2 = 0;

  if (!src)
    goto done;
  if (!dst)
    goto done;
  if (!dstlen)
    goto done;

  len = strlen(src)/2;
  dummy = malloc(len);
  if (!dummy)
    goto done;
  len2 = len;
  unhex(src, dummy, &len2);
  if (len != len2)
    goto done;

  result = 1;

done:
  if (result != 1)
  {
    if (dummy) free(dummy);
  } else {
    *dst = dummy;
    *dstlen = len;
  }
  return result;
}


int encodeasIntX(int i, unsigned char **dst, int *dstlen)
{
  int result = 0;
  unsigned char *tmp = NULL;
  int len = 0;
  char *buf = NULL;

  if (!dst)
    goto done;
  if (!dstlen)
    goto done;

  buf = alloca(16);

  if (i <= 127)
  {
    sprintf(buf, "%02x", i);
  } else if (i <= 16383)
  {
    sprintf(buf, "%04x", i + 0x8000);
  } else if (i <= 2097151)
  {
    sprintf(buf, "%06x", i + 0xC00000);
  } else if (i <= 268435455)
  {
    sprintf(buf, "%08x", i + 0xE0000000);
  } else
    goto done;

  if (!hextobin(buf, &tmp, &len))
    goto done;

  result = 1;

done:
  if (result != 1)
  {
    if (tmp) free(tmp);
  } else {
    *dst = tmp;
    *dstlen = len;
  }
  return result;
}


void dump(unsigned char *data, int len)
{
  int i;

  if (!data)
    goto done;

  for(i = 0; i < len; i++)
  {
    printf("%02x", data[i]);
    if (i%16 == 15)
      printf("\n");
    else
      printf(":");
  }
  printf("\n");

done:
  return;
}


int readfile(char *filename, databuf **filecontent)
{
  int ret = 0;
  FILE *f = NULL;
  databuf *content = NULL;
  void *ptr = NULL;

  if (!filecontent)
    goto done;

  content = malloc(sizeof(*content));
  if (!content)
    goto done;
  content->datalen = 0;
  content->data = NULL;

  f = fopen(filename, "rb");
  if (!f)
    goto done;
  while (!feof(f))
  {
    ptr = realloc(content->data, content->datalen+1024);
    if (!ptr)
      goto done;
    content->data = ptr;
    content->datalen += fread(content->data+content->datalen, 1, 1024, f);
  }

  ret = 1;

done:
  if (f) fclose(f);
  if (ret == 0)
  {
    if (content)
    {
      if (content->data) free(content->data);
      free(content);
    }
  } else {
    *filecontent = content;
  }
  return ret;
}


int writefile(char *filename, databuf *filecontent)
{
  int ret = 0;
  FILE *f = NULL;

  if (!filecontent)
    goto done;

  if (!(filecontent->data))
    goto done;

  f = fopen(filename, "wb");
  if (!f)
  {
    fprintf(stderr, "Ecriture du fichier %s impossible.\n", filename);
    goto done;
  }

  fwrite(filecontent->data, 1, filecontent->datalen, f);
  ret = 1;

done:
  if (f) fclose(f);
  return ret;
}


int pushbuf(databuf *buf, unsigned char *data, unsigned int len)
{
  int ret = 0;
  void *ptr = NULL;

  if (!buf)
    goto done;
  if (!data)
    goto done;

  ptr = realloc(buf->data, buf->datalen+len);
  if (!ptr)
    goto done;
  buf->data = ptr;

  memcpy(buf->data+buf->datalen, data, len);
  buf->datalen += len;

  ret = 1;

done:
  return ret;
}


EC_KEY *readECPrivateKey(char *filename)
{
  BIO *bio = NULL;
  EC_KEY *key = NULL;
  int result = 0;

  bio = BIO_new(BIO_s_file());
  if (!BIO_read_filename(bio, filename))
    goto done;

  key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
  if (!key)
    goto done;

  result = 1;

done:
  if (bio) BIO_free(bio);
  if (result != 1)
    if (key)
    {
      EC_KEY_free(key);
      key = NULL;
    }
  return key;
}


int writeECPrivateKey(char *filename, EC_KEY *key)
{
  BIO *bio = NULL;
  int result = 0;

  bio = BIO_new(BIO_s_file());
  if (!BIO_write_filename(bio, filename))
    goto done;

  if (!PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL))
    goto done;

  BIO_flush(bio);
  
  result = 1;

done:
  if (bio) BIO_free(bio);
  return result;
}


EC_KEY *readECPublicKey(char *filename)
{
  BIO *bio = NULL;
  EC_KEY *key = NULL;
  int result = 0;

  bio = BIO_new(BIO_s_file());
  if (!BIO_read_filename(bio, filename))
    goto done;

  key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
  if (!key)
    goto done;

  result = 1;

done:
  if (bio) BIO_free(bio);
  if (result != 1)
    if (key)
    {
      EC_KEY_free(key);
      key = NULL;
    }
  return key;
}


int encryptccm(databuf *plaintext,
               unsigned char *key, unsigned char *nonce,
               databuf **ciphertext)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int ret = 0;
  databuf *output = NULL;

  /* Perform sanity checks */
  if (!plaintext || !(plaintext->data) || !ciphertext || !key || !nonce)
    goto done;

  /* Create and initialize the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    goto done;

  /* Initialise the encryption operation. */
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1)
    goto done;

  /* Set the nonce length */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCELEN, NULL) != 1)
    goto done;

  /* Set the tag length */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAGLEN, NULL) != 1)
    goto done;

  /* Initialize key and nonce */
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto done;

  /* Provide the total plaintext length */
  if (EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext->datalen) != 1)
    goto done;

  /* Allocate the outpuf buffer */
  output = malloc(sizeof(*output));
  if (!output)
    goto done;
  output->datalen = len+TAGLEN;
  output->data = malloc(output->datalen);
  if (!(output->data))
    goto done;

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can only be called once for this
   */
  if (EVP_EncryptUpdate(ctx, output->data, &len, plaintext->data, plaintext->datalen) != 1)
    goto done;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in CCM mode
   */
  if (EVP_EncryptFinal_ex(ctx, output->data+len, &len) != 1)
    goto done;

  /* Get the tag */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAGLEN, output->data+output->datalen-TAGLEN) != 1)
    goto done;

  /* Gone this far? Everything's right */
  ret = 1;

done:
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  if (ret == 0)
  {
    if (output && output->data) free(output->data);
    if (output) free(output);
  }
  else
    *ciphertext = output;

  return ret;
}


int decryptccm(databuf *ciphertext,
               unsigned char *key, unsigned char *nonce,
               databuf **plaintext)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int ret = 0;
  databuf *output = NULL;

  /* Perform sanity checks */
  if (!ciphertext || !(ciphertext->data) || !plaintext || !key || !nonce)
    goto done;

  /* Check data size according to TAGLEN */
  if (ciphertext->datalen < TAGLEN)
    goto done;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    goto done;

  /* Initialise the decryption operation. */
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1)
    goto done;

  /* Set the nonce length */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCELEN, NULL) != 1)
    goto done;

  /* Set expected tag length and value. */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAGLEN, ciphertext->data+ciphertext->datalen-TAGLEN) != 1)
    goto done;

  /* Initialise key and nonce */
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto done;

  /* Provide the total ciphertext length */
  if (EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext->datalen-TAGLEN) != 1)
    goto done;

  /* Allocate the outpuf buffer */
  output = malloc(sizeof(*output));
  if (!output)
    goto done;
  output->datalen = len;
  output->data = malloc(output->datalen);
  if (!(output->data))
    goto done;

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  ret = EVP_DecryptUpdate(ctx, output->data, &len, ciphertext->data, ciphertext->datalen-TAGLEN);

done:
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  if (ret == 0)
  {
    if (output && output->data) free(output->data);
    if (output) free(output);
  }
  else
    *plaintext = output;

  return ret;
}


void *ETSI_ECIES_KDF(const void *in, size_t inlen, void *out, size_t *outlen)
{
  /* compteur 1..2^32 */
  /* CB=compteur exprimé sur 32 bits en big endian */
  /* SHA256(in||CB) */
  /* compteur++, et on recommence tant qu'on a encore besoin de
   * générer du stream */
  void *ret = NULL;
  int counter = 1;
  unsigned char CB[4];
  unsigned char HB[EVP_MAX_MD_SIZE];
  unsigned int HB_len;
  int outputedlen = 0,
      remains = *outlen;
  EVP_MD_CTX *ctx = NULL;

  ctx = EVP_MD_CTX_create();

  while (remains > 0) {
    CB[0] = counter >> 24;
    CB[1] = (counter >> 16) & 0xff;
    CB[2] = (counter >> 8) & 0xff;
    CB[3] = counter & 0xff;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestUpdate(ctx, CB, sizeof(CB));
    EVP_DigestFinal_ex(ctx, HB, &HB_len);

    if (remains > HB_len)
    {
      memcpy((void*)out+outputedlen, HB, HB_len);
      outputedlen += HB_len;
      remains -= HB_len;
    }
    else
    {
      memcpy((void*)out+outputedlen, HB, remains);
      outputedlen += remains;
      remains -= remains;
    }

    counter++;
  }

  ret = out;

  EVP_MD_CTX_destroy(ctx);
  return ret;
}


unsigned char *hashthis(unsigned char *data, int len, const EVP_MD *md)
{
  int ret = 0;
  EVP_MD_CTX *mdctx = NULL;
  unsigned char *digest = NULL;
  unsigned int digestlen = 0,
               expecteddigestlen = 0;

  if (!md)
    goto done;

  expecteddigestlen = EVP_MD_size(md);
  digest = malloc(expecteddigestlen);
  if (!digest)
    goto done;
  if ((mdctx = EVP_MD_CTX_create()) == NULL)
    goto done;
  if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    goto done;
  if (EVP_DigestUpdate(mdctx, data, len) != 1)
    goto done;
  if (EVP_DigestFinal_ex(mdctx, digest, &digestlen) != 1)
    goto done;
  if (digestlen != expecteddigestlen)
    goto done;

  ret = 1;

done:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  if (!ret)
  {
    if (digest) free(digest);
    digest = NULL;
  }
  return digest;
}


unsigned char *getHashedId8(unsigned char *data, int len)
{
  int ret = 0;
  unsigned char *fullhash = NULL;
  unsigned char *hashedid8 = NULL;

  fullhash = hashthis(data, len, EVP_sha256());
  if (!fullhash)
    goto done;

  hashedid8 = malloc(8);
  if (!hashedid8)
    goto done;

  memcpy(hashedid8, fullhash+24, 8);
  
  ret = 1;

done:
  if (fullhash) free(fullhash);
  if (!ret)
  {
    if (hashedid8) free(hashedid8);
    hashedid8 = NULL;
  }
  return hashedid8;
}
