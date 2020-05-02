#ifndef ENTROPHY_H
#define ENTROPHY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <math.h>
#include "sniffex.h"

struct Entrophy
{
#define max_char 256
#define max_time 100000
    double **x; //store the data
    int W;      //window size
    int I;//interval size
    int i;      //interval number;
    int cnt; //the number of ip

    //sniffex paramaters
    pcap_t *handler;
    struct bpf_program fp;
    int num_packets;
};

static struct Entrophy *buf;

// init some basic paramaters  
void init_entrophy(struct Entrophy **e);

// the callback function
void got_packet_entrophy(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// the procedures of sniff
void sniffex_init(struct Entrophy *e);
void sniffex_start(struct Entrophy *e);
void sniffex_pause();
void sniffex_finish(struct Entrophy *e);

//caculate the entrophy 
double get_entrophy(struct Entrophy *e);

void entrophy_test();

#endif // !ENTROPHY_H
