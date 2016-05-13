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
  char *technicalkeyfile;
  char *canonicalid;
  char *responsedecryptionkeyfile;
  char *verificationkeyfile;
  char *hexitsaidssplist;
  char *encryptionkeyfile;
  char *hexvalidityrestrictions;
  char *eakeyfile;
  char *hexeaid;
  char *outputfile;
  int taiutc;
  int debug;

  // work data
  EC_KEY *technicalKey;
  EC_KEY *verificationKey;
  EC_KEY *encryptionKey;
  EC_KEY *responseDecryptionKey;
  EC_KEY *eaKey;
  unsigned char *eaId;
  unsigned char *itsaidssplist;
  unsigned char *validityrestrictions;
  int itsaidssplist_len;
  int validityrestrictions_len;

} genECEnroll_st;


void printhelp_genECEnroll(void)
{
  printf("genECEnroll [option...]\n");
  printf("\n");

  printf("  -k|--technicalkey <file>\n");
  printf("  -i|--canonicalid <value>\n");
  printf("  -d|--responsedecryptionkey <file>\n");
  printf("  -v|--verificationkey <file>\n");
  printf("  -p|--itsaidssplist <hexvalue>\n");
  printf(" (-e|--encryptionkey <file>)\n");
  printf(" (-r|--validityrestrictions <hexvalue>)\n");
  printf("  -R|--eaid <HashedId8 in hex>\n");
  printf("  -K|--eakey <file>\n");
  printf("  -o|--output <file>\n");
  printf(" (-t|--taiutc <value>)\n");
  printf(" (--debug)\n");
  printf("\n");
  printf("By default, difference between TAI and UTC is equal to " TAIUTCstr " seconds.\n");
  printf("\n");

  exit(1);
}


void init_genECEnroll(int argc, char **argv, genECEnroll_st *options)
{
  int c;

  options->taiutc = TAIUTC;

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      { "technicalkey", 1, 0, 'k' },
      { "canonicalid", 1, 0, 'i' },
      { "responsedecryptionkey", 1, 0, 'd' },
      { "verificationkey", 1, 0, 'v' },
      { "itsaidssplist", 1, 0, 'p' },
      { "encryptionkey", 1, 0, 'e' },
      { "validityrestrictions", 1, 0, 'r' },
      { "eaid", 1, 0, 'R' },
      { "eakey", 1, 0, 'K' },
      { "taiutc", 1, 0, 't' },
      { "output", 1, 0, 'o' },
      { "debug", 0, 0, '_' },
      { "help", 0, 0, 'h' },
      { 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "k:i:d:v:p:e:r:R:K:t:o:_h", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'k':
        if (options->technicalkeyfile) free(options->technicalkeyfile);
        options->technicalkeyfile = strdup(optarg);
        break;

      case 'i':
        if (options->canonicalid) free(options->canonicalid);
        options->canonicalid = strdup(optarg);
        break;

      case 'd':
        if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
        options->responsedecryptionkeyfile = strdup(optarg);
        break;

      case 'v':
        if (options->verificationkeyfile) free(options->verificationkeyfile);
        options->verificationkeyfile = strdup(optarg);
        break;

      case 'p':
        if (options->hexitsaidssplist) free(options->hexitsaidssplist);
        options->hexitsaidssplist = strdup(optarg);
        break;

      case 'e':
        if (options->encryptionkeyfile) free(options->encryptionkeyfile);
        options->encryptionkeyfile = strdup(optarg);
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
        if (options->eakeyfile) free(options->eakeyfile);
        options->eakeyfile = strdup(optarg);
        break;

      case 't':
        options->taiutc = atoi(optarg);
        break;

      case 'o':
        if (options->outputfile) free(options->outputfile);
        options->outputfile = strdup(optarg);
        break;

      case '_':
        options->debug = 1;
        break;

      case 'h':
        printhelp_genECEnroll();
        break;

      case '?':
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        break;
    }
  }

  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc)
      printf("%s ", argv[optind++]);
    printf("\n");
  }
}


void cleanup_genECEnroll(genECEnroll_st *options)
{
  // args
  if (options->hexvalidityrestrictions) free(options->hexvalidityrestrictions);
  if (options->hexitsaidssplist) free(options->hexitsaidssplist);
  if (options->technicalkeyfile) free(options->technicalkeyfile);
  if (options->canonicalid) free(options->canonicalid);
  if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
  if (options->verificationkeyfile) free(options->verificationkeyfile);
  if (options->encryptionkeyfile) free(options->encryptionkeyfile);
  if (options->outputfile) free(options->outputfile);
  if (options->hexeaid) free(options->hexeaid);
  if (options->eakeyfile) free(options->eakeyfile);

  // work data
  if (options->technicalKey) EC_KEY_free(options->technicalKey);
  if (options->verificationKey) EC_KEY_free(options->verificationKey);
  if (options->encryptionKey) EC_KEY_free(options->encryptionKey);
  if (options->responseDecryptionKey) EC_KEY_free(options->responseDecryptionKey);
  if (options->itsaidssplist) free(options->itsaidssplist);
  if (options->validityrestrictions) free(options->validityrestrictions);
  if (options->eaId) free(options->eaId);
  if (options->eaKey) EC_KEY_free(options->eaKey);
}


int verifyargs_genECEnroll(genECEnroll_st *options)
{
  int ret = 0;

  if (!(options->technicalkeyfile))
  {
    fprintf(stderr, "I need a technical key.\n");
    goto done;
  }

  if (!(options->canonicalid))
  {
    fprintf(stderr, "I need a canonical identifier.\n");
    goto done;
  }

  if (!(options->responsedecryptionkeyfile))
  {
    fprintf(stderr, "I need a response decryption key.\n");
    goto done;
  }

  if (!(options->verificationkeyfile))
  {
    fprintf(stderr, "I need a verification key.\n");
    goto done;
  }

  if (!(options->eakeyfile))
  {
    fprintf(stderr, "I need the EA encryption key.\n");
    goto done;
  }

  if (!(options->hexeaid))
  {
    fprintf(stderr, "I need the EA identifier.\n");
    goto done;
  }

  if ((strlen(options->hexeaid)) != 16)
  {
    fprintf(stderr, "The recipient identifier must be 8 octets long.\n");
    goto done;
  }

  if (!(options->hexitsaidssplist))
  {
    fprintf(stderr, "I need an its aid ssp list.\n");
    goto done;
  }

  if ((strlen(options->hexitsaidssplist) % 2) == 1)
  {
    fprintf(stderr, "its aid ssp list length must be even.\n");
    goto done;
  }

  if (!(options->outputfile))
  {
    fprintf(stderr, "I need an output file.\n");
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

  /* Everything's fine so far */
  ret = 1;

done:
  return ret;
}


int genECEnroll(genECEnroll_st *options)
{
  int ret = 0;
  int attrslen = 0;
  unsigned char *subjattrs = NULL;
  unsigned char *intX = NULL;
  int intX_len = 0;
  FILE *out = NULL;
  ISE_PUBLICKEY *key = NULL;
  ISE_INNERECREQUEST *innerECreq = NULL;
  ISE_SIGNEDDATA *signedData = NULL;
  ISE_ENCRYPTEDDATA *encryptedData = NULL;
  ISE_DATA *data = NULL;
  databuf *innerECreqDER = NULL;
  databuf *signedDataDER = NULL;
  databuf *encryptedDataDER = NULL;
  databuf *encryptedpayload = NULL;
  unsigned char *aeskey = NULL;
  unsigned char *aesccmnonce = NULL;

  
  /* Step 1: build the InnerECRequest */
  // TODO: rationalize with genInnerECRequest

  /* Composing the wanted subject attributes */
  /* First, ITSAIDSSPLIST */
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

  /* Next, verification key */
  if (options->verificationKey)
  {
    ISE_PUBLICKEY_set(&key, options->verificationKey);
    if (!key)
      goto done;
    subjattrs = realloc(subjattrs, attrslen+2+1+ASN1_STRING_length(key->x));
    subjattrs[attrslen++] = 0x00;
    subjattrs[attrslen++] = 0x00;
    subjattrs[attrslen++] = ASN1_ENUMERATED_get(key->type) & 0xff;
    memcpy(subjattrs+attrslen, ASN1_STRING_data(key->x), ASN1_STRING_length(key->x));
    attrslen += ASN1_STRING_length(key->x);
  }

  /* Next, encryption key if present */
  if (options->encryptionKey)
  {
    ISE_PUBLICKEY_set(&key, options->encryptionKey);
    if (!key)
      goto done;
    subjattrs = realloc(subjattrs, attrslen+3+1+ASN1_STRING_length(key->x));
    subjattrs[attrslen++] = 0x01;
    subjattrs[attrslen++] = 0x01;
    subjattrs[attrslen++] = 0x00;
    subjattrs[attrslen++] = ASN1_ENUMERATED_get(key->type) & 0xff;
    memcpy(subjattrs+attrslen, ASN1_STRING_data(key->x), ASN1_STRING_length(key->x));
    attrslen += ASN1_STRING_length(key->x);
  }

  /* Build the object */
  innerECreq = buildInnerECRequest(options->canonicalid,
                                   subjattrs, attrslen,
                                   options->validityrestrictions, options->validityrestrictions_len,
                                   options->responseDecryptionKey);
  if (!innerECreq)
    goto done;

  
  /* Step 2: sign this InnerECRequest */
  innerECreqDER = calloc(sizeof(*innerECreqDER), 1);
  if (!innerECreqDER)
    goto done;
  innerECreqDER->datalen = i2d_ISE_INNERECREQUEST(innerECreq, &(innerECreqDER->data));
  if (innerECreqDER->datalen <= 0)
    goto done;
  signedData = buildSignedData(OBJ_nid2obj(NID_ISE_ct_EnrolmentRequest), innerECreqDER, 0);
  if (!signedData)
    goto done;
  if (!signSignedData(signedData, NULL, NULL, options->technicalKey, options->taiutc, 1))
    goto done;


  /* Step 3: encrypt this SignedData */
  //OPENSSL_free(payload->data);
  signedDataDER = calloc(sizeof(*signedDataDER), 1);
  if (!signedDataDER)
    goto done;
  signedDataDER->datalen = i2d_ISE_SIGNEDDATA(signedData, &(signedDataDER->data));
  if (signedDataDER->datalen <= 0)
    goto done;
  genSecretAESCCMParameters(&aeskey, &aesccmnonce);
  if (!aeskey)
    goto done;
  if (!aesccmnonce)
    goto done;
  if (encryptccm(signedDataDER, aeskey, aesccmnonce, &encryptedpayload) != 1)
    goto done;
  encryptedData = buildEncryptedData(OBJ_nid2obj(NID_ISE_ct_SignedData), encryptedpayload, aesccmnonce);
  if (!encryptedData)
    goto done;
  if (!addEncryptedDataRecipient(encryptedData, options->eaId, aeskey, options->eaKey))
    goto done;


  /* Step 4: enclose the EncryptedData into a Data */
  //OPENSSL_free(payload->data);
  encryptedDataDER = calloc(sizeof(*encryptedDataDER), 1);
  if (!encryptedDataDER)
    goto done;
  encryptedDataDER->datalen = i2d_ISE_ENCRYPTEDDATA(encryptedData, &(encryptedDataDER->data));
  if (encryptedDataDER->datalen <= 0)
    goto done;
  data = buildData(OBJ_nid2obj(NID_ISE_ct_EncryptedData), encryptedDataDER);
  if (!data)
    goto done;


  /* Output the result in DER */
  out = fopen(options->outputfile, "wb");
  i2d_ISE_DATA_fp(out, data);
  fclose(out);

  /* Everything's fine */
  ret = 1;

done:
  /* Cleanup */
  if (subjattrs) free(subjattrs);
  if (innerECreq) ISE_INNERECREQUEST_free(innerECreq);
  if (signedData) ISE_SIGNEDDATA_free(signedData);
  if (key) ISE_PUBLICKEY_free(key);
  if (intX) free(intX);
  if (innerECreqDER)
  {
    if (innerECreqDER->data) OPENSSL_free(innerECreqDER->data);
    free(innerECreqDER);
  }
  if (signedDataDER)
  {
    if (signedDataDER->data) OPENSSL_free(signedDataDER->data);
    free(signedDataDER);
  }
  if (encryptedDataDER)
  {
    if (encryptedDataDER->data) OPENSSL_free(encryptedDataDER->data);
    free(encryptedDataDER);
  }
  if (encryptedpayload)
  {
    if (encryptedpayload->data) free(encryptedpayload->data);
    free(encryptedpayload);
  }
  if (encryptedData) ISE_ENCRYPTEDDATA_free(encryptedData);
  if (data) ISE_DATA_free(data);
  if (aeskey) free(aeskey);
  if (aesccmnonce) free(aesccmnonce);
  return ret;
}


int main_genECEnroll(int argc, char **argv)
{
  int ret = EXIT_FAILURE;
  genECEnroll_st *options = NULL;
  int i = 0;

  options = calloc(sizeof(*options), 1);

  init_genECEnroll(argc, argv, options);

  if (!verifyargs_genECEnroll(options))
    goto done;

  if (!(options->technicalKey = readECPrivateKey(options->technicalkeyfile)))
  {
    fprintf(stderr, "Unable to read technical key.\n");
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

  if (!(options->responseDecryptionKey = readECPrivateKey(options->responsedecryptionkeyfile)))
  {
    fprintf(stderr, "Unable to read response decryption key.\n");
    goto done;
  }

  if (!(options->eaKey = readECPublicKey(options->eakeyfile)))
  {
    fprintf(stderr, "Unable to read EA encryption key.\n");
    goto done;
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

  if (!genECEnroll(options))
  {
    fprintf(stderr, "EC enrolment request generation failed.\n");
    goto done;
  }

  ret = EXIT_SUCCESS;

done:
  cleanup_genECEnroll(options);
  return ret;
}
