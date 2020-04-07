#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "correlation.h"


int init_cor(char *dev)
{
    //init some variables
    h = (struct hash *)malloc(sizeof(struct hash));
    init_hash(&h);
    print_hash(h);

    char *errbuf = (char *)malloc(sizeof(char) * PCAP_ERRBUF_SIZE);

    filter_exp="ip";

    if (dev == NULL)
    {
        if (get_dev(&dev, &errbuf) == -1)
        {
            printf("device error: %s\n", errbuf);
            return -1;
        }
    }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        // exit(EXIT_FAILURE);
        return -1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        // exit(EXIT_FAILURE);
        return -1;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        // exit(EXIT_FAILURE);
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        // exit(EXIT_FAILURE);
        return -1;
    }
    return 1;
}

void got_packet_cor(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 0;
    printf("num %d\n", ++count);

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const char *payload;                   /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet *)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;/*the length of the header of the ip packet*/
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    /* print the generate hash code*/
    // print_hash(h);
    printf("       The Hash code is: %d\n",generate_hash(h,ip->ip_src.s_addr));
    
}

void sigalarm_cor()
{
    // static int intervel = 0;
    pcap_breakloop(handle);
    // printf("intervel %d:\n", ++intervel);
    return;
}

void start_capture_cor()
{
    alarm(1);
    signal(SIGALRM, sigalarm_cor);
    pcap_loop(handle, -1, got_packet_cor, NULL);
}

void finish_capture_cor()
{
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("capture finished!\n");
}

void correlation()
{
    int w;//the window size

    init_cor(NULL);
    int t = 20;
    while (t--)
    {
        start_capture_cor();
    }
    finish_capture_cor();
}