#include "ise_asn1.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "isetoolbox.h"


// TODO: ajouter plus de traces de debug


typedef struct {
  // args
  char *enrollmentcertificatefile;
  char *signaturekeyfile;
  char *responsedecryptionkeyfile;
  char *verificationkeyfile;
  char *encryptionkeyfile;
  char *hexitsaidssplist;
  char *hexvalidityrestrictions;
  char *hexeaid;
  char *eaencryptionkeyfile;
  char *hexaaid;
  char *aaencryptionkeyfile;
  char *outputfile;
  int wantedstart;
  int taiutc;
  int debug;

  // work data
  unsigned char *ecid;
  EC_KEY *signatureKey;
  EC_KEY *responseDecryptionKey;
  EC_KEY *verificationKey;
  EC_KEY *encryptionKey;
  unsigned char *itsaidssplist;
  int itsaidssplist_len;
  unsigned char *validityrestrictions;
  int validityrestrictions_len;
  unsigned char *eaId;
  EC_KEY *eaEncryptionKey;
  unsigned char *aaId;
  EC_KEY *aaEncryptionKey;
} genATEnroll_st;


void printhelp_genATEnroll(void)
{
  printf("genATEnroll [option...]\n");
  printf("\n");

  printf("  -c|--enrolmentcertificate <file>\n");
  printf("  -k|--signaturekey <file>\n");
  printf("  -d|--responsedecryptionkey <file>\n");
  printf("  -v|--verificationkey <file>\n");
  printf(" (-e|--encryptionkey <file>)\n");
  printf("  -p|--itsaidssplist <hexvalue>\n");
  printf(" (-r|--validityrestrictions <hexvalue>)\n");
  printf("  -R|--eaid <HashedId8 in hex>\n");
  printf("  -K|--eaencryptionkey <file>\n");
  printf("  -a|--aaid <HashedId8 in hex>\n");
  printf("  -A|--aaencryptionkey <file>\n");
  printf("  -o|--output <file>\n");
  printf(" (-s|--start <integer>)\n");
  printf(" (-t|--taiutc <value>)\n");
  printf(" (--debug)\n");
  printf("\n");
  printf("By default, difference between TAI and UTC is equal to " TAIUTCstr " seconds.\n");
  printf("\n");  

  exit(1);
}


void init_genATEnroll(int argc, char **argv, genATEnroll_st *options)
{
  int c;

  options->taiutc = TAIUTC;
  options->wantedstart = time(NULL)-1072915200;
  
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      { "enrolmentcertificate", 1, 0, 'c' },
      { "signaturekey", 1, 0, 'k' },
      { "responsedecryptionkey", 1, 0, 'd' },
      { "verificationkey", 1, 0, 'v' },
      { "encryptionkey", 1, 0, 'e' },
      { "itsaidssplist", 1, 0, 'p' },
      { "validityrestrictions", 1, 0, 'r' },
      { "eaid", 1, 0, 'R' },
      { "eaencryptionkey", 1, 0, 'K' },
      { "aaid", 1, 0, 'a' },
      { "aaencryptionkey", 1, 0, 'A' },
      { "output", 1, 0, 'o' },
      { "start", 0, 0, 's' },
      { "taiutc", 1, 0, 't' },
      { "debug", 0, 0, '_' },
      { "help", 0, 0, 'h' },
      { 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "c:k:d:v:e:p:r:R:K:a:A:o:st:_h", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'c':
        if (options->enrollmentcertificatefile) free(options->enrollmentcertificatefile);
        options->enrollmentcertificatefile = strdup(optarg);
        break;

      case 'k':
        if (options->signaturekeyfile) free(options->signaturekeyfile);
        options->signaturekeyfile = strdup(optarg);
        break;

      case 'd':
        if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
        options->responsedecryptionkeyfile = strdup(optarg);
        break;

      case 'v':
        if (options->verificationkeyfile) free(options->verificationkeyfile);
        options->verificationkeyfile = strdup(optarg);
        break;

      case 'e':
        if (options->encryptionkeyfile) free(options->encryptionkeyfile);
        options->encryptionkeyfile = strdup(optarg);
        break;

      case 'p':
        if (options->hexitsaidssplist) free(options->hexitsaidssplist);
        options->hexitsaidssplist = strdup(optarg);
        break;

      case 'r':
        if (options->hexvalidityrestrictions) free(options->hexvalidityrestrictions);
        options->hexvalidityrestrictions = strdup(optarg);
        break;

      case 'R':
        if (options->hexeaid) free(options->hexeaid);
        options->hexeaid = strdup(optarg);
        break;

      case 'K':
        if (options->eaencryptionkeyfile) free(options->eaencryptionkeyfile);
        options->eaencryptionkeyfile = strdup(optarg);
        break;

      case 'a':
        if (options->hexaaid) free(options->hexaaid);
        options->hexaaid = strdup(optarg);
        break;

      case 'A':
        if (options->aaencryptionkeyfile) free(options->aaencryptionkeyfile);
        options->aaencryptionkeyfile = strdup(optarg);
        break;

      case 'o':
        if (options->outputfile) free(options->outputfile);
        options->outputfile = strdup(optarg);
        break;

      case 's':
        options->wantedstart = atoi(optarg);
        break;

      case 't':
        options->taiutc = atoi(optarg);
        break;

      case '_':
        options->debug = 1;
        break;

      case 'h':
        printhelp_genATEnroll();
        break;

      case '?':
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        break;
    }
  }

  options->wantedstart += options->taiutc;
  
  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc)
      printf("%s ", argv[optind++]);
    printf("\n");
  }
}


void cleanup_genATEnroll(genATEnroll_st *options)
{
  // args
  if (options->enrollmentcertificatefile) free(options->enrollmentcertificatefile);
  if (options->signaturekeyfile) free(options->signaturekeyfile);
  if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
  if (options->verificationkeyfile) free(options->verificationkeyfile);
  if (options->encryptionkeyfile) free(options->encryptionkeyfile);
  if (options->hexitsaidssplist) free(options->hexitsaidssplist);
  if (options->hexvalidityrestrictions) free(options->hexvalidityrestrictions);
  if (options->hexeaid) free(options->hexeaid);
  if (options->eaencryptionkeyfile) free(options->eaencryptionkeyfile);
  if (options->hexaaid) free(options->hexaaid);
  if (options->aaencryptionkeyfile) free(options->aaencryptionkeyfile);
  if (options->outputfile) free(options->outputfile);

  // work data
  if (options->ecid) free(options->ecid);
  if (options->signatureKey) EC_KEY_free(options->signatureKey);
  if (options->responseDecryptionKey) EC_KEY_free(options->responseDecryptionKey);
  if (options->verificationKey) EC_KEY_free(options->verificationKey);
  if (options->encryptionKey) EC_KEY_free(options->encryptionKey);
  if (options->itsaidssplist) free(options->itsaidssplist);
  if (options->validityrestrictions) free(options->validityrestrictions);
  if (options->eaId) free(options->eaId);
  if (options->eaEncryptionKey) EC_KEY_free(options->eaEncryptionKey);
  if (options->aaId) free(options->aaId);
  if (options->aaEncryptionKey) EC_KEY_free(options->aaEncryptionKey);
}


int verifyargs_genATEnroll(genATEnroll_st *options)
{
  int ret = 0;

  if (!options->enrollmentcertificatefile)
  {
    fprintf(stderr, "I need an enrolment certificate.\n");
    goto done;
  }

  if (!options->signaturekeyfile)
  {
    fprintf(stderr, "I need a signature key file.\n");
    goto done;
  }

  if (!options->responsedecryptionkeyfile)
  {
    fprintf(stderr, "I need a response decryption key.\n");
    goto done;
  }

  if (!options->verificationkeyfile)
  {
    fprintf(stderr, "I need a verification key.\n");
    goto done;
  }

  if (!options->hexitsaidssplist)
  {
    fprintf(stderr, "I need an its aid ssp list.\n");
    goto done;
  }

  if ((strlen(options->hexitsaidssplist) % 2) == 1)
  {
    fprintf(stderr, "its aid ssp list length must be even.\n");
    goto done;
  }

  if (options->hexvalidityrestrictions)
  {
    if ((strlen(options->hexvalidityrestrictions) % 2) == 1)
    {
      fprintf(stderr, "validity restrictions length must be even.\n");
      goto done;
    }
  }

  if (!options->hexeaid)
  {
    fprintf(stderr, "I need the EA identifier.\n");
    goto done;
  }

  if (!options->eaencryptionkeyfile)
  {
    fprintf(stderr, "I need the EA encryption key.\n");
    goto done;
  }

  if (!options->hexaaid)
  {
    fprintf(stderr, "I need the AA identifier.\n");
    goto done;
  }

  if (!options->aaencryptionkeyfile)
  {
    fprintf(stderr, "I need the AA encryption key.\n");
    goto done;
  }

  if (!options->outputfile)
  {
    fprintf(stderr, "I need an output file.\n");
    goto done;
  }

  /* Everything's fine so far */
  ret = 1;

done:
  return ret;
}


int genATEnroll(genATEnroll_st *options)
{
  int ret = 0;
  FILE *out = NULL;
  BIO *dbg = NULL;
  unsigned char hmackey[32];
  unsigned char hmac_result[EVP_MAX_MD_SIZE];
  unsigned int hmac_len = 0;
  unsigned char keytag[16];
  ISE_PUBLICKEY *verifkey = NULL,
                *encrkey = NULL;
  databuf *encodedkeys = NULL,
          *sharedATreqDER = NULL,
          *signedDataSharedDER = NULL,
          *encryptedpayloadShared = NULL,
          *encryptedpayloadInner = NULL,
          *innerATreqDER = NULL,
          *encryptedDataInnerDER = NULL;
  unsigned char *p = NULL;
  int len1 = 0, len2 = 0, i = 0;
  int attrslen = 0;
  unsigned char *subjattrs = NULL;
  unsigned char *intX = NULL;
  int intX_len = 0;
  ISE_SHAREDATREQUEST *sharedATreq = NULL;
  ISE_SIGNEDDATA *signedDataShared = NULL;
  ISE_ENCRYPTEDDATA *encryptedDataShared = NULL,
                    *encryptedDataInner = NULL;
  ISE_INNERATREQUEST *innerATreq = NULL;
  ISE_DATA *data = NULL;
  unsigned char *aeskeyShared = NULL,
                *aesccmnonceShared = NULL,
                *aeskeyInner = NULL,
                *aesccmnonceInner = NULL;


  dbg = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (!dbg)
    goto done;

  /* Step 1: build the SharedATRequest */
  if (options->debug)
    BIO_puts(dbg, "### Build the SharedATRequest\n\n");

  /* We need to calculate an HMAC on the keys, let's generate an HMAC key */
  RAND_pseudo_bytes(hmackey, sizeof(hmackey));
  if (options->debug)
  {
    BIO_puts(dbg, "Generated HMAC key:\n");
    BIO_dump_indent(dbg, (char*)&hmackey, sizeof(hmackey), 2);
    BIO_puts(dbg, "\n");
  }

  /* Encode the verification key and encryption key */
  ISE_PUBLICKEY_set(&verifkey, options->verificationKey);
  if (!verifkey)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "Verification key\n");
    ISE_PUBLICKEY_print_ctx(dbg, verifkey, 0, NULL);
    BIO_puts(dbg, "\n");
  }
  if (options->encryptionKey)
  {
    ISE_PUBLICKEY_set(&encrkey, options->encryptionKey);
    if (!encrkey)
      goto done;
    if (options->debug)
    {
      BIO_puts(dbg, "Encryption key\n");
      ISE_PUBLICKEY_print_ctx(dbg, encrkey, 0, NULL);
      BIO_puts(dbg, "\n");
    }
  }
  len1 = i2d_ISE_PUBLICKEY(verifkey, NULL);
  if (len1 <= 0)
    goto done;
  if (encrkey)
  {
    len2 = i2d_ISE_PUBLICKEY(encrkey, NULL);
    if (len2 <= 0)
      goto done;
  }
  encodedkeys = calloc(sizeof(*encodedkeys), 1);
  if (!encodedkeys)
    goto done;
  encodedkeys->datalen = len1+len2;
  encodedkeys->data = calloc(encodedkeys->datalen, 1);
  if (!encodedkeys->data)
    goto done;
  p = encodedkeys->data;
  i = i2d_ISE_PUBLICKEY(verifkey, &p);
  if (i != len1)
    goto done;
  if (encrkey)
  {
    i = i2d_ISE_PUBLICKEY(encrkey, &p);
    if (i != len2)
      goto done;
  }
  if (options->debug)
  {
    BIO_puts(dbg, "Encoded keys:\n");
    BIO_dump_indent(dbg, (char*)(encodedkeys->data), encodedkeys->datalen, 2);
    BIO_puts(dbg, "\n");
  }


  /* Calculate the HMAC on this */
  if (HMAC(EVP_sha256(), hmackey, sizeof(hmackey), encodedkeys->data, encodedkeys->datalen, hmac_result, &hmac_len) == NULL)
    goto done;
  memcpy(keytag, hmac_result, sizeof(keytag));
  if (options->debug)
  {
    BIO_puts(dbg, "Calculated HMAC tag:\n");
    BIO_dump_indent(dbg, (char*)&keytag, sizeof(keytag), 2);
    BIO_puts(dbg, "\n");
  }


  /* Composing the wanted subject attributes */
  // TODO: rationalize with genInnerECRequest
  if (options->itsaidssplist)
  {
    if (!encodeasIntX(options->itsaidssplist_len, &intX, &intX_len))
      goto done;
    subjattrs = malloc(1+intX_len+options->itsaidssplist_len);
    subjattrs[attrslen++] = 0x21;
    memcpy(subjattrs+attrslen, intX, intX_len);
    attrslen += intX_len;
    memcpy(subjattrs+attrslen, options->itsaidssplist, options->itsaidssplist_len);
    attrslen += options->itsaidssplist_len;
  }
  if (options->debug)
  {
    BIO_puts(dbg, "AID-SSP list:\n");
    BIO_dump_indent(dbg, (char*)subjattrs, attrslen, 2);
    BIO_puts(dbg, "\n");
  }

  /* Build the object */
  sharedATreq = buildSharedATRequest(options->eaId, keytag,
                                     subjattrs, attrslen,
                                     options->validityrestrictions, options->validityrestrictions_len,
                                     options->wantedstart, options->responseDecryptionKey);
  if (!sharedATreq)
    goto done;

  if (options->debug)
  {
    ISE_SHAREDATREQUEST_print_ctx(dbg, sharedATreq, 0, NULL);
    BIO_puts(dbg, "\n");
  }

  /* Step 2: sign this SharedATRequest, detached signature */
  if (options->debug)
    BIO_puts(dbg, "### Sign this SharedATRequest\n\n");
  sharedATreqDER = calloc(sizeof(*sharedATreqDER), 1);
  if (!sharedATreqDER)
    goto done;
  sharedATreqDER->datalen = i2d_ISE_SHAREDATREQUEST(sharedATreq, &(sharedATreqDER->data));
  if (sharedATreqDER->datalen <= 0)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "SharedATRequest DER encoded:\n");
    BIO_dump_indent(dbg, (char*)(sharedATreqDER->data), sharedATreqDER->datalen, 2);
    BIO_puts(dbg, "\n");
  }
  signedDataShared = buildSignedData(OBJ_nid2obj(NID_ISE_ct_SharedATRequest), NULL /*sharedATreqDER*/, 1);
  if (!signedDataShared)
    goto done;
  if (!signSignedData(signedDataShared, sharedATreqDER, options->ecid, options->signatureKey, options->taiutc, 1))
    goto done;

  if (options->debug)
  {
    ISE_SIGNEDDATA_print_ctx(dbg, signedDataShared, 0, NULL);
    BIO_puts(dbg, "\n");
  }

  /* Step 3: encrypt this stuff for the EA */
  if (options->debug)
    BIO_puts(dbg, "### Encrypt the signed SharedATRequest for the EA\n\n");
  signedDataSharedDER = calloc(sizeof(*signedDataSharedDER), 1);
  if (!signedDataSharedDER)
    goto done;
  signedDataSharedDER->datalen = i2d_ISE_SIGNEDDATA(signedDataShared, &(signedDataSharedDER->data));
  if (signedDataSharedDER->datalen <= 0)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "SignedData DER encoded:\n");
    BIO_dump_indent(dbg, (char*)(signedDataSharedDER->data), signedDataSharedDER->datalen, 2);
    BIO_puts(dbg, "\n");
  }
  genSecretAESCCMParameters(&aeskeyShared, &aesccmnonceShared);
  if (!aeskeyShared)
    goto done;
  if (!aesccmnonceShared)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "AES key:\n");
    BIO_dump_indent(dbg, (char*)aeskeyShared, KEYLEN, 2);
    BIO_puts(dbg, "CCM nonce:\n");
    BIO_dump_indent(dbg, (char*)aesccmnonceShared, NONCELEN, 2);
    BIO_puts(dbg, "\n");
  }
  if (encryptccm(signedDataSharedDER, aeskeyShared, aesccmnonceShared, &encryptedpayloadShared) != 1)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "AES-CCM-encrypted content:\n");
    BIO_dump_indent(dbg, (char*)(encryptedpayloadShared->data), encryptedpayloadShared->datalen, 2);
    BIO_puts(dbg, "\n");
  }
  encryptedDataShared = buildEncryptedData(OBJ_nid2obj(NID_ISE_ct_SignedData), encryptedpayloadShared, aesccmnonceShared);
  if (!encryptedDataShared)
    goto done;
  if (!addEncryptedDataRecipient(encryptedDataShared, options->eaId, aeskeyShared, options->eaEncryptionKey))
    goto done;

  if (options->debug)
  {
    ISE_ENCRYPTEDDATA_print_ctx(dbg, encryptedDataShared, 0, NULL);
    BIO_puts(dbg, "\n");
  }

  /* Step 4: build the InnerATRequest */
  if (options->debug)
    BIO_puts(dbg, "### Build the InnerATRequest\n\n");
  innerATreq = buildInnerATRequest(verifkey, encrkey, hmackey, sharedATreq, encryptedDataShared);
  if (!innerATreq)
    goto done;

  if (options->debug)
  {
    ISE_INNERATREQUEST_print_ctx(dbg, innerATreq, 0, NULL);
    BIO_puts(dbg, "\n");
  }

  /* Step 5: encrypt this InnerATRequest for the AA */
  if (options->debug)
    BIO_puts(dbg, "### Encrypt this InnerATRequest for the AA\n\n");
  innerATreqDER = calloc(sizeof(*innerATreqDER), 1);
  if (!innerATreqDER)
    goto done;
  innerATreqDER->datalen = i2d_ISE_INNERATREQUEST(innerATreq, &(innerATreqDER->data));
  if (innerATreqDER->datalen <= 0)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "InnerATRequest DER encoded:\n");
    BIO_dump_indent(dbg, (char*)(innerATreqDER->data), innerATreqDER->datalen, 2);
    BIO_puts(dbg, "\n");
  }
  genSecretAESCCMParameters(&aeskeyInner, &aesccmnonceInner);
  if (!aeskeyInner)
    goto done;
  if (!aesccmnonceInner)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "AES key:\n");
    BIO_dump_indent(dbg, (char*)aeskeyInner, KEYLEN, 2);
    BIO_puts(dbg, "CCM nonce:\n");
    BIO_dump_indent(dbg, (char*)aesccmnonceInner, NONCELEN, 2);
    BIO_puts(dbg, "\n");
  }
  if (encryptccm(innerATreqDER, aeskeyInner, aesccmnonceInner, &encryptedpayloadInner) != 1)
    goto done;
  if (options->debug)
  {
    BIO_puts(dbg, "AES-CCM-encrypted content:\n");
    BIO_dump_indent(dbg, (char*)(encryptedpayloadInner->data), encryptedpayloadInner->datalen, 2);
    BIO_puts(dbg, "\n");
  }
  encryptedDataInner = buildEncryptedData(OBJ_nid2obj(NID_ISE_ct_AuthorizationRequest), encryptedpayloadInner, aesccmnonceInner);
  if (!encryptedDataInner)
    goto done;
  if (!addEncryptedDataRecipient(encryptedDataInner, options->aaId, aeskeyInner, options->aaEncryptionKey))
    goto done;

  if (options->debug)
  {
    ISE_ENCRYPTEDDATA_print_ctx(dbg, encryptedDataInner, 0, NULL);
    BIO_puts(dbg, "\n");
  }


  /* Step 6: enclose this EncryptedData into a Data */
  if (options->debug)
    BIO_puts(dbg, "### Enclose the EncryptedData into a Data\n\n");
  encryptedDataInnerDER = calloc(sizeof(*encryptedDataInnerDER), 1);
  if (!encryptedDataInnerDER)
    goto done;
  encryptedDataInnerDER->datalen = i2d_ISE_ENCRYPTEDDATA(encryptedDataInner, &(encryptedDataInnerDER->data));
  if (encryptedDataInnerDER->datalen <= 0)
    goto done;
  data = buildData(OBJ_nid2obj(NID_ISE_ct_EncryptedData), encryptedDataInnerDER);
  if (!data)
    goto done;

  if (options->debug)
  {
    ISE_DATA_print_ctx(dbg, data, 0, NULL);
    BIO_puts(dbg, "\n");
  }

  /* Output the result in DER */
  out = fopen(options->outputfile, "wb");
  i2d_ISE_DATA_fp(out, data);
  fclose(out);

  /* Everything's fine */
  ret = 1;

done:
  /* Cleanup */
  if (dbg)
  {
    BIO_flush(dbg);
    BIO_free(dbg);
  }
  if (verifkey) ISE_PUBLICKEY_free(verifkey);
  if (encrkey) ISE_PUBLICKEY_free(encrkey);
  if (encodedkeys)
  {
    if (encodedkeys->data) free(encodedkeys->data);
    free(encodedkeys);
  }
  if (subjattrs) free(subjattrs);
  if (sharedATreq) ISE_SHAREDATREQUEST_free(sharedATreq);
  if (sharedATreqDER)
  {
    if (sharedATreqDER->data) OPENSSL_free(sharedATreqDER->data);
    free(sharedATreqDER);
  }
  if (signedDataShared) ISE_SIGNEDDATA_free(signedDataShared);
  if (signedDataSharedDER)
  {
    if (signedDataSharedDER->data) OPENSSL_free(signedDataSharedDER->data);
    free(signedDataSharedDER);
  }
  if (aeskeyShared) free(aeskeyShared);
  if (aesccmnonceShared) free(aesccmnonceShared);
  if (encryptedpayloadShared)
  {
    if (encryptedpayloadShared->data) free(encryptedpayloadShared->data);
    free(encryptedpayloadShared);
  }
  if (encryptedDataShared) ISE_ENCRYPTEDDATA_free(encryptedDataShared);
  if (innerATreq) ISE_INNERATREQUEST_free(innerATreq);
  if (innerATreqDER)
  {
    if (innerATreqDER->data) OPENSSL_free(innerATreqDER->data);
    free(innerATreqDER);
  }
  if (aeskeyInner) free(aeskeyInner);
  if (aesccmnonceInner) free(aesccmnonceInner);
  if (encryptedpayloadInner)
  {
    if (encryptedpayloadInner->data) free(encryptedpayloadInner->data);
    free(encryptedpayloadInner);
  }
  if (encryptedDataInner) ISE_ENCRYPTEDDATA_free(encryptedDataInner);
  if (encryptedDataInnerDER)
  {
    if (encryptedDataInnerDER->data) OPENSSL_free(encryptedDataInnerDER->data);
    free(encryptedDataInnerDER);
  }
  if (data) ISE_DATA_free(data);

  return ret;
}


int main_genATEnroll(int argc, char **argv)
{
  int ret = EXIT_FAILURE;
  genATEnroll_st *options = NULL;
  databuf *data = NULL;
  int i = 0;

  options = calloc(sizeof(*options), 1);

  init_genATEnroll(argc, argv, options);

  if (!verifyargs_genATEnroll(options))
    goto done;

  readfile(options->enrollmentcertificatefile, &data);
  if (!data)
  {
    fprintf(stderr, "Unable to read the enrollment certificate.\n");
    goto done;
  }
  options->ecid = getHashedId8(data->data, data->datalen);
  if (!options->ecid)
  {
    fprintf(stderr, "Unable to calculate the ECId.\n");
    goto done;
  }
  free(data->data);
  free(data);
  data = NULL;

  if (!(options->signatureKey = readECPrivateKey(options->signaturekeyfile)))
  {
    fprintf(stderr, "Unable to read signature key.\n");
    goto done;
  }
  
  if (!(options->responseDecryptionKey = readECPrivateKey(options->responsedecryptionkeyfile)))
  {
    fprintf(stderr, "Unable to read the response decryption.\n");
    goto done;
  }

  if (!(options->verificationKey = readECPrivateKey(options->verificationkeyfile)))
  {
    fprintf(stderr, "Unable to read verification key.\n");
    goto done;
  }

  if (options->encryptionkeyfile)
  {
    if (!(options->encryptionKey = readECPrivateKey(options->encryptionkeyfile)))
    {
      fprintf(stderr, "Unable to read encryption key.\n");
      goto done;
    }
  }

  if (!hextobin(options->hexitsaidssplist, &(options->itsaidssplist), &(options->itsaidssplist_len)))
  {
    fprintf(stderr, "Badly formatted ITS AID SSP list.\n");
    goto done;
  }

  if (options->hexvalidityrestrictions)
  {
    if (!hextobin(options->hexvalidityrestrictions, &(options->validityrestrictions), &(options->validityrestrictions_len)))
    {
      fprintf(stderr, "Badly formatted validity restrictions.\n");
      goto done;
    }
  }

  if (!hextobin(options->hexeaid, &(options->eaId), &i))
  {
    fprintf(stderr, "Badly formatted EA identifier.\n");
    goto done;
  }
  if (i != 8)
  {
    fprintf(stderr, "EA identifier must be 8 octets long.\n");
    goto done;
  }

  if (!(options->eaEncryptionKey = readECPublicKey(options->eaencryptionkeyfile)))
  {
    fprintf(stderr, "Unable to read EA encryption key.\n");
    goto done;
  }

  if (!hextobin(options->hexaaid, &(options->aaId), &i))
  {
    fprintf(stderr, "Badly formatted AA identifier.\n");
    goto done;
  }
  if (i != 8)
  {
    fprintf(stderr, "AA identifier must be 8 octets long.\n");
    goto done;
  }

  if (!(options->aaEncryptionKey = readECPublicKey(options->aaencryptionkeyfile)))
  {
    fprintf(stderr, "Unable to read AA encryption key.\n");
    goto done;
  }

  if (!genATEnroll(options))
    goto done;

  ret = EXIT_SUCCESS;

done:
  if (data)
  {
    if (data->data) free(data->data);
    free(data);
  }
  cleanup_genATEnroll(options);
  return ret;
}
