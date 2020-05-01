#ifndef CORRELATION_H
#define CORRELATION_H

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include "sniffex.h"
#include "hash.h"
#include "myrbtree.h"

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
static myrb_tree T;

static int **X;                     //to store the data
static const int max_ip = 1000;     //max num of ip
static const int max_time = 100000; // max num of interval
static int ip_num;                  //the num of ip
static int interval_num;            //the num of interval
static int w;                       //the window size
static FILE *outfile;               //the file to store the pxy
static int count=0;
/*functions*/
int init_cor(char *dev);

void got_packet_cor(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void start_capture_cor();

void finish_capture_cor();

double get_cov();

double get_entrophy();

void correlation();

#endif // !CORRELATION_H
