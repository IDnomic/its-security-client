#include "ise_asn1.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <getopt.h>

#include "genkey.h"
#include "receiveECResponse.h"
#include "genECEnroll.h"
#include "genATEnroll.h"
#include "receiveATResponse.h"



struct functiontable {
    char *fnctname;
    int (*fnctmain)(int argc, char **argv);
};

struct functiontable allmains[] = {
    { "genkey", main_genKey },
    { "genECEnroll", main_genECEnroll },
    { "genATEnroll", main_genATEnroll },
    { "receiveECResponse", main_receiveECResponse },
    { "receiveATResponse", main_receiveATResponse },
    { NULL, NULL }
};


void printhelp(void)
{
    int i;

    printf("iseclient cmd [args...]\n");
    printf("\n");
    printf("cmd can be:\n");

    for(i = 0; allmains[i].fnctmain; i++)
        printf("  %s\n", allmains[i].fnctname);

    printf("\n");
    printf("cmd is case insensitive.\n");
    exit(1);
}


int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    char *cmd = NULL;
    int i = 0;

    addISEoids();

    if (argc < 2)
        printhelp();
    cmd = strdup(argv[1]);
    argc--;
    memmove(argv+1, argv+2, sizeof(*argv)*(argc-1));

    for(i = 0; allmains[i].fnctmain; i++)
        if (!strcasecmp(cmd, allmains[i].fnctname))
        {
            ret = (allmains[i].fnctmain)(argc, argv);
            break;
        }

    if (!allmains[i].fnctmain)
        printhelp();

    if (cmd) free(cmd);
    ERR_print_errors_fp(stderr);
    return ret;
}
