#ifndef CORRELATION_H
#define CORRELATION_H

#include "sniffex.h"
#include "hash.h"

/*
some needed variables
to make it effective in this source file
*/
static pcap_t *handle;
static struct hash *h;
static char *filter_exp;
static struct bpf_program fp;
static bpf_u_int32 mask;
static bpf_u_int32 net;

int init_cor(char *dev);

void got_packet_cor(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void start_capture_cor();

void finish_capture_cor();

void correlation();


#endif // !CORRELATION_H
