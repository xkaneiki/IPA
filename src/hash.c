#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"

void init_hash(struct hash **h)
{
    (*h) = (struct hash *)malloc(sizeof(struct hash));
    (*h)->cnt = 0;
    (*h)->prime = 9973;
    memset((*h)->asn, 0, sizeof (*h)->asn);
    return;
}

int generate_hash(struct hash *h, u_int ip)
{
    if (h->cnt >= h->prime)
        return -1;
    int hv = (int)((long long)ip % h->prime);
    while (h->asn[hv] != 0 && h->asn[hv] != ip)
        hv++;
    if (h->asn[hv] == 0)
    {
        h->asn[hv] = ip;
        h->cnt++;
    }
    return hv;
}

void print_hash(struct hash *h){
    printf("hash information:\n");
    printf("         cnt: %d\n",h->cnt);
    printf("       prime: %d\n",h->prime);
}
