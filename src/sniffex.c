#include <stdio.h>
#include <stdlib.h>
#include "sniffex.h"

int getDev(char *NAME,char *ERR)
{
    ERR=(char *)malloc(PCAP_ERRBUF_SIZE*sizeof(char));
    NAME = pcap_lookupdev(ERR);
    if (NAME == NULL)
    {
        fprintf(stderr, "couldn't find default device: %s\n", ERR);
        return 0;
    }
    printf("Device: %s\n", NAME);
    return 1;
}