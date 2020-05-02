#include "entrophy.h"

void init_entrophy(struct Entrophy **e)
{
    *e = (struct Entrophy *)malloc(sizeof(struct Entrophy));
    //set the space to store data
    (*e)->x = (double **)malloc(max_char * sizeof(double *));
    for (int i = 0; i < max_char; i++)
    {
        (*e)->x[i] = (double *)malloc(max_time * sizeof(double));
        memset((*e)->x[i], 0, sizeof((*e)->x[i]));
    }
    (*e)->W = 3;
    (*e)->I = 1;
    (*e)->i = 0;
    (*e)->cnt = 0;
    return;
}

void sniffex_init(struct Entrophy *e)
{
    char *dev = NULL;              /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

    char filter_exp[] = "ip"; /* filter expression [3] */

    bpf_u_int32 mask;     /* subnet mask */
    bpf_u_int32 net;      /* ip */
    int num_packets = -1; /* number of packets to capture */

    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
        exit(EXIT_FAILURE);
    }
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    e->handler = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (e->handler == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(e->handler) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(e->handler, &(e->fp), filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(e->handler));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(e->handler, &(e->fp)) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(e->handler));
        exit(EXIT_FAILURE);
    }

    return;
}

void got_packet_entrophy(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //get the arguments
    struct Entrophy *e = (struct Entrophy *)(args);

    //count ip packets
    e->cnt++;
    printf("ip%d\n", e->cnt);

    const struct sniff_ethernet *ethernet_header;
    const struct sniff_ip *ip_header;

    // get the ethernet head
    ethernet_header = (struct sniff_ethernet *)(packet);

    // get the ip head
    ip_header = (struct sniff_ip *)(packet + SIZE_ETHERNET);

    //retore the data
    int header_len = (int)((ip_header->ip_vhl) & 0x0f) * 32;
    u_char *attr = (u_char *)(ip_header);
    while (header_len)
    {
        e->x[*attr][e->i]++;
        attr = attr + 1;
        header_len--;
    }
    return;
}

//caculate the entrophy of this window
double get_entrophy(struct Entrophy *e)
{
    double sum = 0;
    for (int c = 0; c < max_char; c++)
    {
        double p = 0;
        for (int w = 0; w < e->W; w++)
            p += e->x[c][((e->i) - w + max_time) % max_time];
        sum += p;
    }
    if (sum == 0)
        return 0;
    double H = 0;
    for (int c = 0; c < max_char; c++)
    {
        double p = 0;
        for (int w = 0; w < e->W; w++)
            p += e->x[c][((e->i) - w + max_time) % max_time];
        p /= sum;
        if (p > 0)
            H -= p * log2(p);
    }
    return H;
}

void sniffex_start(struct Entrophy *e)
{
    buf = e;                                                                 //pass the paramaters
    alarm(e->W);                                                             //start timer
    signal(SIGALRM, sniffex_pause);                                          //set callback function for alarm
    pcap_loop(e->handler, e->num_packets, got_packet_entrophy, (u_char *)e); //start sniff and pass the arguments to the call bac
}

void sniffex_pause()
{
    struct Entrophy *e = buf;
    pcap_breakloop(e->handler);
    printf("this interval %d\n", e->i);
    if (e->i >= e->W)
    {
        double H = get_entrophy(e);
        printf("%lf\n", H);
    }
    e->i++;
}

void sniffex_finish(struct Entrophy *e)
{
    /* cleanup */
    pcap_freecode(&(e->fp));
    pcap_close(e->handler);
    printf("total packet:%d\n", e->cnt);
    printf("\nCapture complete.\n");
}

void entrophy_test()
{
    struct Entrophy *e;
    init_entrophy(&e);
    int t = 60;
    sniffex_init(e);
    while (t--)
        sniffex_start(e);
    sniffex_finish(e);
    return;
}