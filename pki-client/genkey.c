#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <getopt.h>
#include "isetoolbox.h"


#define ERR_LIB_GENKEY 129
#define GENERR(f,r) ERR_PUT_error(ERR_LIB_GENKEY,(f),(r),__FILE__,__LINE__)


// TODO: more debug log

typedef struct {
    char *outputfile;
    int explicitcurve;
    int compressed;
    int debug;
} genKey_st;


void printhelp_genKey(void)
{
    printf("genKey [option...]\n");
    printf("\n");
    printf("  -o|--output <file>\n");
    printf("  -c|--compressed\n");
    printf("  -e|--explicitcurve\n");
    printf(" (--debug)\n");
    exit(1);
}


void init_genKey(int argc, char **argv, genKey_st *options)
{
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "output", 1, 0, 'o' },
            { "compressed", 0, 0, 'c' },
            { "explicitcurve", 0, 0, 'e' },
            { "debug", 0, 0, '_' },
            { "help", 0, 0, 'h' },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "o:ce_h", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'o':
                if (options->outputfile) free(options->outputfile);
                options->outputfile = strdup(optarg);
                break;

            case 'c':
                options->compressed = 1;
                break;

            case 'e':
                options->explicitcurve = 1;
                break;

            case '_':
                options->debug = 1;
                break;

            case 'h':
                printhelp_genKey();
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


void cleanup_genKey(genKey_st *options)
{
    if (options->outputfile) free(options->outputfile);
}


int verifyargs_genKey(genKey_st *options)
{
    int ret = 0;

    if (!(options->outputfile))
    {
        fprintf(stderr, "I need an output file.\n");
        GENERR(-1, ERR_R_PASSED_NULL_PARAMETER);
        ERR_add_error_data(1, "I need an output file.");
        goto done;
    }

    /* Everything's fine so far */
    ret = 1;

done:
    return ret;
}


int genKey(genKey_st *options)
{
    int ret = 0;
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;

    key = EC_KEY_new();
    if (!key)
        goto done;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)
        goto done;

    if (!(options->explicitcurve))
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_set_group(key, group) == 0)
        goto done;

    if (!EC_KEY_generate_key(key))
        goto done;

    if (options->compressed)
        EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

    if (options->debug)
    {
        LOGMSG(LOGINDENT(options->debug), "Generated key:");
        EC_KEY_print_fp(stdout, key, LOGINDENT(options->debug));
    }

    if (!writeECPrivateKey(options->outputfile, key))
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    if (group) EC_GROUP_free(group);
    if (key) EC_KEY_free(key);
    return ret;
}


int main_genKey(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    genKey_st *options = NULL;

    options = calloc(sizeof(*options), 1);

    init_genKey(argc, argv, options);

    if (!verifyargs_genKey(options))
        goto done;

    if (!genKey(options))
    {
        fprintf(stderr, "Key generation failed.\n");
        goto done;
    }

    ret = EXIT_SUCCESS;

done:
    cleanup_genKey(options);
    return ret;
}
