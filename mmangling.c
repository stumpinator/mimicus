#include "mmangling.h"
#include "mimicus.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

static char TCPO_EOL[] =     {0x00};
static char TCPO_NOP[] =     {0x01};
static char TCPO_MSS[] =     {0x02,0x04,0x00,0x00};
static char TCPO_SCALE[] =   {0x03,0x03,0x00};
static char TCPO_SOK[] =     {0x04,0x02};
static char TCPO_TS[] =      {0x08,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int set_tcp_winsize(struct tcphdr *tcph, uint16_t sz)
{
    tcph->window = htons(sz);
    return MIMICUS_TCP_CS;
}

int set_ipid_nonzero(struct iphdr *iph)
{
    if (iph->id != 0) return 0;
    iph->id = 1;
    return MIMICUS_IP_CS;
}

int set_df(struct iphdr *iph, uint8_t f)
{
    char *fo = (char *)&iph->frag_off;
    uint8_t df = *fo & 0x40;

    if (f > 0) f = 0x40;

    //no need to continue if setting is already what is requested
    if (df == f) return 0;

    if (f == 0)
    {
        *fo = *fo ^ 0x40;
    }
    else
    {
        *fo = *fo | 0x40;
    }
    return MIMICUS_IP_CS;
}

void tcp_checksum(struct iphdr * iph)
{
    unsigned long sum = 0;
    unsigned short tcplen = ntohs(iph->tot_len) - (iph->ihl << 2);
    struct tcphdr *tcph = (struct tcphdr *)(((void *)iph) + (iph->ihl << 2));
    unsigned short * tcpdat = (unsigned short *)tcph;

    //printf("TCP len: %d\n", tcplen);
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr & 0xFFFF);
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr & 0xFFFF);
    sum += htons(IPPROTO_TCP);
    sum += htons(tcplen);
    tcph->check = 0;

    while (tcplen > 1)
    {
        sum += *tcpdat++;
        tcplen -= 2;
    }
    if (tcplen > 0)
    {
        //printf("tcp_checksum padding\n");
        sum += ((*tcpdat) & htons(0xFF00));
    }
    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    tcph->check = ~(unsigned short)sum;

    //printf("source: %d\n", ntohs(tcph->source));
    //printf("dest: %d\n", ntohs(tcph->dest));
    //printf("doff: %d\n", tcph->doff);
}

void udp_checksum(struct iphdr * iph)
{
    unsigned long sum = 0;
    struct udphdr *udph = (struct udphdr *)(((void *)iph) + (iph->ihl << 2));
    unsigned short udplen = udph->len;
    unsigned short * udpdat = (unsigned short *)udph;

    //printf("TCP len: %d\n", tcplen);
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr & 0xFFFF);
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr & 0xFFFF);
    sum += htons(IPPROTO_UDP);
    sum += udph->len;
    udph->check = 0;

    while (udplen > 1)
    {
        sum += *udpdat++;
        udplen -= 2;
    }
    if (udplen > 0)
    {
        //printf("tcp_checksum padding\n");
        sum += ((*udpdat) & htons(0xFF00));
    }
    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;
    udph->check = ((unsigned short)sum == 0) ? 0xFFFF : (unsigned short)sum;

    //printf("source: %d\n", ntohs(tcph->source));
    //printf("dest: %d\n", ntohs(tcph->dest));
    //printf("doff: %d\n", tcph->doff);
}

void ip_checksum(struct iphdr * iph)
{

    unsigned int count;
    unsigned short * ipdat;
    unsigned long sum;

    iph->check = 0;
    count = iph->ihl << 2;
    ipdat = (unsigned short *)iph;
    sum = 0;

    //count up bytes of ip header
    while (count > 1)
    {
        sum += *ipdat++;
        count -= 2;
    }

    //if odd number, pad 0s
    if (count > 0)
    {
        sum += ((*ipdat) & htons(0xFF00));
    }

    //add carries
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iph->check = ~(unsigned short)sum;
}

int resize_tcpopts(struct iphdr *iph, struct tcphdr *tcph, uint8_t offs)
{
    void *tcppl;
    int res = 0;
    uint16_t pload_len = 0;

    if ((offs >= 5) && (tcph->doff != offs))
    {
        pload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
        tcppl = ((void *)tcph) + (tcph->doff << 2);
        tcph->doff = offs;

        //the buffer size should be big enough that moving around the options here is no problem
        tcppl = memmove((void *)tcph + (offs << 2), tcppl, pload_len);

        iph->tot_len = htons((iph->ihl << 2) + (tcph->doff << 2) + pload_len);
        res = MIMICUS_IP_CS | MIMICUS_TCP_CS;
    }

    return res;
}

int write_tcp_opt(void **tcpop, enum tcp_opt_type otype, struct tcpoptions *to)
{
    int ret = MIMICUS_TCP_CS;

    switch (otype)
    {
        case OPT_EOL:
            memcpy(*tcpop, &TCPO_EOL, sizeof(TCPO_EOL));
            *tcpop += sizeof(TCPO_EOL);
            break;
        case OPT_NOP:
            memcpy(*tcpop, &TCPO_NOP, sizeof(TCPO_NOP));
            *tcpop += sizeof(TCPO_NOP);
            break;
        case OPT_MSS:
            memcpy(*tcpop, &TCPO_MSS, sizeof(TCPO_MSS));
            memcpy(*tcpop + 2, &to->mss, 2);
            *tcpop += sizeof(TCPO_MSS);
            break;
        case OPT_SCALE:
            memcpy(*tcpop, &TCPO_SCALE, sizeof(TCPO_SCALE));
            memcpy(*tcpop + 2, &to->scale, 1);
            *tcpop += sizeof(TCPO_SCALE);
            break;
        case OPT_SOK:
            memcpy(*tcpop, &TCPO_SOK, sizeof(TCPO_SOK));
            *tcpop += sizeof(TCPO_SOK);
            break;
        case OPT_TS:
            memcpy(*tcpop, &TCPO_TS, sizeof(TCPO_TS));
            memcpy(*tcpop + 2, &to->ts1, 4);
            memcpy(*tcpop + 6, &to->ts2, 4);
            *tcpop += sizeof(TCPO_TS);
            break;
        default:
            ret = 0;
            break;
    }

    return ret;
}

struct tcpoptions* scan_tcpopts(char *opts, int olen)
{
    int count = 0;
    struct tcpoptions *tcpo;
    char a;

    tcpo = calloc(1, sizeof(struct tcpoptions));
    if (!tcpo) return NULL;

    while (count < olen)
    {
        a = *(opts + count);
        if ((a == 0x0) || (a == 0x1))
        {
            count++;
        }
        else if (a == 0x2)
        {
            memcpy(&tcpo->mss, (opts + count + 2), 2);
            count += 4;
        }
        else if (a == 0x3)
        {
            tcpo->o |= MIMICUS_SCALE;
            tcpo->scale = *(opts + count + 2);
            count += 3;
        }
        else if (a == 0x4)
        {
            tcpo->o |= MIMICUS_SOK;
            count += 2;
        }
        else if (a == 0x8)
        {
            tcpo->o |= MIMICUS_TS;
            memcpy(&tcpo->ts1, (opts + count + 2), 4);
            memcpy(&tcpo->ts1, (opts + count + 6), 4);
            count += 10;
        }
        else
        {
            count += *((uint8_t *)(opts + count + 1));
        }
    }
    return tcpo;
}
