#include <stdio.h>
#include <stdlib.h>

#include "tpm/tpm_api.h"

int main (int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    if (tpm_fast_clear()) {
        printf("main() tpmt_fast_clear error\n");
        exit(1);
    }


    return 0;
}
