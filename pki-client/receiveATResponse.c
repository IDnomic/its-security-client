#include "ise_asn1.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "isetoolbox.h"

// TODO: more debug log

typedef struct {
    // args
    char *inputfile;
    char *outputfile;
    char *responsedecryptionkeyfile;
    char *aaverificationkeyfile;
    char *requestfile;
    char *hexaaid;
    int debug;
    // work data
    EC_KEY *responseDecryptionKey;
    EC_KEY *aaVerificationKey;
    unsigned char *aaId;
    unsigned char *wantedrequesthash;
} receiveATResponse_st;


void printhelp_receiveATResponse(void)
{
    printf("receiveATResponse [option...]\n");
    printf("\n");
    printf("  -i|--input <file>\n");
    printf("  -o|--output <file>\n");
    printf("  -k|--responsedecryptionkey <key>\n");
    printf("  -v|--aaverificationkey <key>\n");
    printf("  -a|--aaid <HashedId8 in hex>\n");
    printf(" (-r|--request <file>)\n");
    printf(" (--debug)\n");
    exit(1);
}


void init_receiveATResponse(int argc, char **argv, receiveATResponse_st *options)
{
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "input", 1, 0, 'i' },
            { "output", 1, 0, 'o' },
            { "responsedecryptionkey", 1, 0, 'k' },
            { "aaverificationkey", 1, 0, 'v' },
            { "aaid", 1, 0, 'a' },
            { "request", 1, 0, 'r' },
            { "debug", 0, 0, '_' },
            { "help", 0, 0, 'h' },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "i:o:k:v:a:r:h", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                if (options->inputfile) free(options->inputfile);
                options->inputfile = strdup(optarg);
                break;

            case 'o':
                if (options->outputfile) free(options->outputfile);
                options->outputfile = strdup(optarg);
                break;

            case 'k':
                if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
                options->responsedecryptionkeyfile = strdup(optarg);
                break;

            case 'v':
                if (options->aaverificationkeyfile) free(options->aaverificationkeyfile);
                options->aaverificationkeyfile = strdup(optarg);
                break;

            case 'a':
                if (options->hexaaid) free(options->hexaaid);
                options->hexaaid = strdup(optarg);
                break;

            case 'r':
                if (options->requestfile) free(options->requestfile);
                options->requestfile = strdup(optarg);
                break;

            case '_':
                options->debug = 1;
                break;

            case 'h':
                printhelp_receiveATResponse();
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


void cleanup_receiveATResponse(receiveATResponse_st *options)
{
    // args
    if (options->inputfile) free(options->inputfile);
    if (options->outputfile) free(options->outputfile);
    if (options->responsedecryptionkeyfile) free(options->responsedecryptionkeyfile);
    if (options->aaverificationkeyfile) free(options->aaverificationkeyfile);
    if (options->hexaaid) free(options->hexaaid);
    if (options->requestfile) free(options->requestfile);
    // work data
    if (options->responseDecryptionKey) EC_KEY_free(options->responseDecryptionKey);
    if (options->aaVerificationKey) EC_KEY_free(options->aaVerificationKey);
    if (options->aaId) free(options->aaId);
    if (options->wantedrequesthash) free(options->wantedrequesthash);
}


int verifyargs_receiveATResponse(receiveATResponse_st *options)
{
    int ret = 0;

    if (!(options->inputfile))
    {
        fprintf(stderr, "I need an input file.\n");
        goto done;
    }

    if (!(options->outputfile))
    {
        fprintf(stderr, "I need an output file.\n");
        goto done;
    }

    if (!(options->responsedecryptionkeyfile))
    {
        fprintf(stderr, "I need a response decryption key.\n");
        goto done;
    }

    if (!(options->aaverificationkeyfile))
    {
        fprintf(stderr, "I need an AA verification key.\n");
        goto done;
    }

    if (!(options->hexaaid))
    {
        fprintf(stderr, "I need an AA identifier.\n");
        goto done;
    }

    if (strlen(options->hexaaid) != 16)
    {
        fprintf(stderr, "AA identifier length must be 16 characters long.\n");
        goto done;
    }

    /* Everything's fine so far */
    ret = 1;

done:
    return ret;
}


int receiveATResponse(receiveATResponse_st *options)
{
    int ret = 0;
    FILE *f = NULL;
    ISE_DATA *data = NULL;
    ISE_ENCRYPTEDDATA *encryptedData = NULL;
    ISE_SIGNEDDATA *signedData = NULL;
    ISE_INNERATRESPONSE *innerATResponse = NULL;
    BIO *biomem = NULL;
    BIO *out = NULL;
    unsigned char *myHashedId8 = NULL;
    databuf *outputbuf = NULL;
    int certificateacceptable = 0;

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!out)
        goto done;

    f = fopen(options->inputfile, "rb");
    if (!f)
        goto done;
    data = d2i_ISE_DATA_fp(f, &data);
    fclose(f);
    f = NULL;

    /* Check that I could read a Data */
    if (!data)
        goto done;

    if (options->debug)
    {
        ISE_DATA_print_ctx(out, data, 0, NULL);
        BIO_flush(out);
    }

    /* Check that it's a known version */
    if ((data->version) && (ASN1_INTEGER_get(data->version) != 0))
        goto done;

    /* We're also waiting for a content */
    if (!(data->content))
        goto done;

    /* I expect either:
     * - encryptedData(SignedData(InnerATResponse)) and a positive response
     * - encryptedData(SignedData(InnerATResponse)) and a negative response
     * - SignedData(InnerATResponse) and a negative response
     */
    if (OBJ_obj2nid(data->contentType) == NID_ISE_ct_EncryptedData)
    {
        /* Prepare to parse the content */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, data->content->data, data->content->length);

        /* Decode the EncryptedData object */
        encryptedData = d2i_ISE_ENCRYPTEDDATA_bio(biomem, &encryptedData);
        BIO_free(biomem);
        biomem = NULL;
        if (!encryptedData)
            goto done;

        if (options->debug)
        {
            ISE_ENCRYPTEDDATA_print_ctx(out, encryptedData, 0, NULL);
            BIO_flush(out);
        }

        /* Next content MUST be a SignedData */
        if (OBJ_obj2nid(encryptedData->encryptedContentType) != NID_ISE_ct_SignedData)
            goto done;

        /* I need to know my hashedid8, based on my responsedecryptionkey */
        if (!(myHashedId8 = ISE_PUBLICKEY_HashedId8(options->responseDecryptionKey)))
            goto done;

        /* Decrypt the thing */
        if (!decrypt_ISE_ENCRYPTEDDATA(encryptedData, myHashedId8, options->responseDecryptionKey, &outputbuf))
            goto done;

        /* Prepare to parse the decrypted content */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, outputbuf->data, outputbuf->datalen);

        /* Decode the SignedData object */
        signedData = d2i_ISE_SIGNEDDATA_bio(biomem, &signedData);
        BIO_free(biomem);
        biomem = NULL;
        if (!signedData)
            goto done;

        if (options->debug)
        {
            ISE_SIGNEDDATA_print_ctx(out, signedData, 0, NULL);
            BIO_flush(out);
        }

        /* Next content MUST be an InnerATResponse */
        if (OBJ_obj2nid(signedData->signedContentType) != NID_ISE_ct_AuthorizationResponse)
            goto done;

        /* Check the signature */
        if (!verifySignedData(signedData, options->aaId, options->aaVerificationKey))
            goto done;

        /* Prepare to parse the signed content */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, signedData->signedContent->data, signedData->signedContent->length);

        /* Decode the InnerATResponse object */
        innerATResponse = d2i_ISE_INNERATRESPONSE_bio(biomem, &innerATResponse);
        BIO_free(biomem);
        biomem = NULL;
        if (!innerATResponse)
            goto done;

        if (options->debug)
        {
            ISE_INNERATRESPONSE_print_ctx(out, innerATResponse, 0, NULL);
            BIO_flush(out);
        }

        /* I don't know the effective AA result code yet, but at this stage, a certificate is acceptable */
        certificateacceptable = 1;
    }
    else if (OBJ_obj2nid(data->contentType) == NID_ISE_ct_SignedData)
    {
        /* Prepare to parse the content */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, data->content->data, data->content->length);

        /* Decode the SignedData object */
        signedData = d2i_ISE_SIGNEDDATA_bio(biomem, &signedData);
        BIO_free(biomem);
        biomem = NULL;
        if (!signedData)
            goto done;

        if (options->debug)
        {
            ISE_SIGNEDDATA_print_ctx(out, signedData, 0, NULL);
            BIO_flush(out);
        }

        /* Next content MUST be an InnerATResponse */
        if (OBJ_obj2nid(signedData->signedContentType) != NID_ISE_ct_AuthorizationResponse)
            goto done;

        /* Check the signature */
        if (!verifySignedData(signedData, options->aaId, options->aaVerificationKey))
            goto done;

        /* Prepare to parse the signed content */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, signedData->signedContent->data, signedData->signedContent->length);

        /* Decode the InnerATResponse object */
        innerATResponse = d2i_ISE_INNERATRESPONSE_bio(biomem, &innerATResponse);
        BIO_free(biomem);
        biomem = NULL;
        if (!innerATResponse)
            goto done;

        if (options->debug)
        {
            ISE_INNERATRESPONSE_print_ctx(out, innerATResponse, 0, NULL);
            BIO_flush(out);
        }
    }
    else
        goto done;

    /* Check the returned InnerATResponse */
    if (!(innerATResponse->requestHash) || (innerATResponse->requestHash->length != 16))
    {
        fprintf(stderr, "RequestHash in response is absent or has wrong length.\n");
        goto done;
    }
    if (options->wantedrequesthash && memcmp(options->wantedrequesthash, innerATResponse->requestHash->data, 16))
    {
        fprintf(stderr, "RequestHash in response doesn't match the request.\n");
        goto done;
    }
    if (ASN1_ENUMERATED_get(innerATResponse->responseCode) != 0)
    {
        printf("AA has returned an error: %ld\n", ASN1_ENUMERATED_get(innerATResponse->responseCode));
        if (innerATResponse->certificate)
            fprintf(stderr, "AA returned a negative answer and a certificate.\n");
        if (innerATResponse->cAContributionValue)
            fprintf(stderr, "AA returned a negative answer and a CAContributionValue.\n");
        goto done;
    }
    if (innerATResponse->cAContributionValue)
    {
        fprintf(stderr, "AA returned a positive answer with a CAContributionValue, this isn't supported.\n");
        goto done;
    }
    if (!(innerATResponse->certificate))
    {
        fprintf(stderr, "AA returned a positive answer without any certificate.\n");
        goto done;
    }
    if (!certificateacceptable)
    {
        fprintf(stderr, "EA returned a signed response without encryption for a positive result, which is noncompliant.\n");
        goto done;
    }

    /* Output the resulting certificate */
    f = fopen(options->outputfile, "wb");
    fwrite(innerATResponse->certificate->data, innerATResponse->certificate->length, 1, f);
    fclose(f);
    f = NULL;

    /* Everything's fine */
    ret = 1;

done:
    /* Cleanup */
    if (out) BIO_free(out);
    if (f) fclose(f);
    if (data) ISE_DATA_free(data);
    if (encryptedData) ISE_ENCRYPTEDDATA_free(encryptedData);
    if (signedData) ISE_SIGNEDDATA_free(signedData);
    if (biomem) BIO_free(biomem);
    if (myHashedId8) free(myHashedId8);
    if (outputbuf) { if (outputbuf->data) free(outputbuf->data); free(outputbuf); }
    if (innerATResponse) ISE_INNERATRESPONSE_free(innerATResponse);
    return ret;
}


int main_receiveATResponse(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    receiveATResponse_st *options = NULL;
    int aaId_len = 0;
    databuf *request = NULL;

    options = calloc(sizeof(*options), 1);

    init_receiveATResponse(argc, argv, options);

    if (!verifyargs_receiveATResponse(options))
        goto done;

    if (!(options->responseDecryptionKey = readECPrivateKey(options->responsedecryptionkeyfile)))
    {
        fprintf(stderr, "Unable to read response decryption key.\n");
        goto done;
    }

    if (!(options->aaVerificationKey = readECPublicKey(options->aaverificationkeyfile)))
    {
        fprintf(stderr, "Unable to read AA verification key.\n");
        goto done;
    }

    if (!hextobin(options->hexaaid, &(options->aaId), &aaId_len))
    {
        fprintf(stderr, "Badly formatted AA identifier.\n");
        goto done;
    }
    if (aaId_len != 8)
    {
        fprintf(stderr, "AA Identifier must be 8 octets long.\n");
        goto done;
    }

    if (options->requestfile)
    {
        if (readfile(options->requestfile, &request) != 1)
        {
            fprintf(stderr, "Unable to read request file.");
            goto done;
        }
        options->wantedrequesthash = hashthis(request->data, request->datalen, EVP_sha256());
        if (!(options->wantedrequesthash))
        {
            fprintf(stderr, "Unable to hash the request.\n");
            goto done;
        }
    }

    if (!receiveATResponse(options))
        goto done;

    ret = EXIT_SUCCESS;

done:
    cleanup_receiveATResponse(options);
    return ret;
}
