#include "correlation.h"

int init_cor(char *dev)
{
    //init some variables
    // h = (struct hash *)malloc(sizeof(struct hash));
    // init_hash(&h);
    // print_hash(h);
    T = NULL;         //to store ip address
    w = 3;            //the window size
    interval_num = 0; //the num of interval
    ip_num = 0;
    outfile = fopen("cor.txt", "w");
    count = 0;

    /*set space to save the data*/
    X = (int **)malloc(max_ip * sizeof(int *));
    for (int i = 0; i < max_ip; i++)
    {
        X[i] = (int *)malloc(max_time * sizeof(int));
        // clear
        memset(X[i], 0, sizeof X[i]);
    }

    char *errbuf = (char *)malloc(sizeof(char) * PCAP_ERRBUF_SIZE);

    filter_exp = "ip";

    if (dev == NULL)
    {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
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
    //static int count = 0;
    //printf("num %d\n", ++count);
    count++;

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
    size_ip = IP_HL(ip) * 4; /*the length of the header of the ip packet*/
    if (size_ip < 20)
    {
        //printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    //printf("       From: %s\n", inet_ntoa(ip->ip_src));
    // printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    /* print the generate hash code*/
    // print_hash(h);
    // printf("       The Hash code is: %d\n", generate_hash(h, ip->ip_src.s_addr));

    /*record the ip address*/
    struct myrb_node *p;
    p = myrb_insert(&T, ip->ip_src.s_addr);
    if (p->sval == -1)
    {
        p->sval = ip_num++;
    }
    X[p->sval][interval_num]++;
}

void sigalarm_cor()
{
    //finish the loop
    pcap_breakloop(handle);

    // get the cov of this window
    printf("interal %d finish!\n", interval_num);
    if (interval_num >= w)
    {
        double cov, ent;
        cov = get_cov();
        ent = get_entrophy();
        printf("%lf\t%lf\n", cov, ent);
        fprintf(outfile, "%lf\t%lf\n", cov, ent);
    }
    printf("\n");
    // move window
    interval_num = (interval_num + 1) % max_time;
    return;
}

void start_capture_cor()
{
    // clear
    alarm(1);
    signal(SIGALRM, sigalarm_cor);
    pcap_loop(handle, -1, got_packet_cor, NULL);
}

void finish_capture_cor()
{
    fclose(outfile);
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("capture finished!\n");
}

double get_cov()
{
    //caculte the sum of each windows
    double sum0 = 0, sum1 = 0;
    for (int ip = 0; ip < ip_num; ip++)
    {
        for (int j = 0; j < w; j++)
        {
            sum0 += X[ip][(interval_num - j + max_time) % max_time];
            sum1 += X[ip][(interval_num - (j + 1) + max_time) % max_time];
        }
    }

    printf("Sum0:%lf\n", sum0);
    printf("Sum1:%lf\n", sum1);

    if (sum0 == 0 || sum1 == 0)
    {
        return 0;
    }
    //caculate the Expection of each window
    double E0 = 0, E1 = 0;
    for (int ip = 0; ip < ip_num; ip++)
    {
        double t0 = 0, t1 = 0;
        for (int j = 0; j < w; j++)
        {
            t0 += X[ip][(interval_num - j + max_time) % max_time];
            t1 += X[ip][(interval_num - (j + 1) + max_time) % max_time];
        }
        E0 += t0 * (t0 / sum0);
        E1 += t1 * (t1 / sum1);
    }
    printf("E0:%lf\n", E0);
    printf("E1:%lf\n", E1);

    // caculate the var of each window and the cov of two adjacent windows
    double COV = 0, D0 = 0, D1 = 0;
    for (int ip = 0; ip < ip_num; ip++)
    {
        double t0 = 0, t1 = 0;
        for (int j = 0; j < w; j++)
        {
            t0 += X[ip][(interval_num - j + max_time) % max_time];
            t1 += X[ip][(interval_num - (j + 1) + max_time) % max_time];
        }
        COV += (t0 - E0) * (t1 - E1);
        D0 += (t0 - E0) * (t0 - E0);
        D1 += (t1 - E1) * (t1 - E1);
    }
    printf("D0:%lf\n", D0);
    printf("D1:%lf\n", D1);
    printf("COV:%lf\n", COV);

    // caculate the pxy and return
    double pxy = COV / (sqrt(D0) * sqrt(D1));
    printf("pxy:%lf\n", pxy);
    return pxy;
}

double get_entrophy()
{
    double sum = 0;
    for (int ip = 0; ip < ip_num; ip++)
    {
        double t = 0;
        for (int j = 0; j < w; j++)
            t += X[ip][(interval_num - j + max_time) % max_time];
        sum += t;
    }
    if (sum == 0)
        return 0;
    double H = 0;
    for (int ip = 0; ip < ip_num; ip++)
    {
        double t = 0;
        for (int j = 0; j < w; j++)
            t += X[ip][(interval_num - j + max_time) % max_time];
        double p = t / sum;
        if (p)
            H -= p * log2(p);
    }
    return H;
}
void correlation()
{
    // inverval is 1s

    init_cor(NULL);

    int t = 40;
    while (t--)
    {
        start_capture_cor();
    }

    finish_capture_cor();

    // print some information
    printf("max num of ip is: %d\n", max_ip);
    printf("the num of ip address is: %d\n", ip_num);
    printf("the count of ip pacp is: %d\n", count);
    printf("max num of interval time is: %d\n", max_time);

    return;
}