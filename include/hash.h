#ifndef HASH_H
#define HASH_H

typedef unsigned int u_int;
#define HASH_LEN 10000

struct hash
{
    /* data */
    int cnt;
    u_int asn[HASH_LEN+10];
    int prime;
};

void init_hash(struct hash **h);

int generate_hash(struct hash *h,u_int ip);

void print_hash(struct hash *h);

#endif // !HASH_H