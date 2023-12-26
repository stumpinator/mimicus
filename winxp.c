#include "mmangler.h"
#include "mimicus.h"
#include "mmangling.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

/*
 * Mangler for ip traffic to look like windows xp
 *
 * SYN
 *
 * TTL = 128
 * IPv4 option length = 0
 * MSS = any
 * window size = 65535
 * window scaling factor = 0,1,2
 *  \x02\x04\x05\xb4\x01\x03\x03\x01\x01\x01\x04\x02
 *  |  MSS 1460     | N |  SCALE 1  | N | N |  SOK  |
 * don't fragment bit
 * IPID non-zero
 */

static int mmangle_tcp(char *buf, int *plen);
//static int mmangle_udp(char *buf, int *plen);

extern int mmangle_ip(char *buf, int *plen)
{
    struct iphdr *iph;
    int res = 0;

    iph = (struct iphdr *)buf;

    if (iph->version == 4)
    {
        if (iph->ttl != 128)
        {
            //printf("setting ttl to 128\n");
            iph->ttl = 128;
            res |= MIMICUS_IP_CS;
        }

        if (iph->protocol == IPPROTO_TCP)
        {
            res |= mmangle_tcp(buf, plen);
        }
    }

    if (res & MIMICUS_IP_CS)
    {
        ip_checksum(iph);
    }
    if (res & MIMICUS_TCP_CS)
    {
        tcp_checksum(iph);
    }

    return res;
}

int mmangle_tcp(char *buf, int *plen)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct tcpoptions *tcpo;
    void *tcpopts;
    int res = 0;

    iph = (struct iphdr *)buf;
    tcph = (struct tcphdr *)(((void *)iph) + (iph->ihl << 2));
    if (!tcph->syn) return res;

    tcpopts = (void *)tcph + 20;

    tcpo = scan_tcpopts((char *)tcph + 20, (tcph->doff << 2) - 20);
    if (!tcpo) return res;

    //DF bit
    res |= set_df(iph, 1);
    //window size
    res |= set_tcp_winsize(tcph, 65535);
    //id+
    res |= set_ipid_nonzero(iph);

    if (tcph->ack)
    {
        //printf("SYN/ACK\n");
        if (tcpo->o == 0)
        {
            res |= resize_tcpopts(iph, tcph, 6);
            //addo_mss(&tcpopts, tcpo->mss);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
        }
        else if (tcpo->o == MIMICUS_SCALE)
        {
            res |= resize_tcpopts(iph, tcph, 7);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_scale(&tcpopts, 0);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->scale = 0;
            write_tcp_opt(&tcpopts, OPT_SCALE, tcpo);
        }
        else if (tcpo->o == MIMICUS_SOK)
        {
            res |= resize_tcpopts(iph, tcph, 7);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_sok(&tcpopts);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_SOK, tcpo);
        }
        else if (tcpo->o == MIMICUS_TS)
        {
            res |= resize_tcpopts(iph, tcph, 9);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_ts(&tcpopts, 0, tcpo->ts2);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->ts1 = 0;
            write_tcp_opt(&tcpopts, OPT_TS, tcpo);
        }
        else if (tcpo->o == (MIMICUS_SCALE | MIMICUS_SOK))
        {
            res |= resize_tcpopts(iph, tcph, 8);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_scale(&tcpopts, 0);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_sok(&tcpopts);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->scale = 0;
            write_tcp_opt(&tcpopts, OPT_SCALE, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_SOK, tcpo);
        }
        else if (tcpo->o == (MIMICUS_SCALE | MIMICUS_TS))
        {
            res |= resize_tcpopts(iph, tcph, 10);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_scale(&tcpopts, 0);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_ts(&tcpopts, 0, tcpo->ts2);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->scale = 0;
            write_tcp_opt(&tcpopts, OPT_SCALE, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->ts1 = 0;
            write_tcp_opt(&tcpopts, OPT_TS, tcpo);
        }
        else if (tcpo->o == (MIMICUS_TS | MIMICUS_SOK))
        {
            res |= resize_tcpopts(iph, tcph, 10);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_ts(&tcpopts, 0, tcpo->ts2);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_sok(&tcpopts);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->ts1 = 0;
            write_tcp_opt(&tcpopts, OPT_TS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_SOK, tcpo);
        }
        else if (tcpo->o == (MIMICUS_SCALE | MIMICUS_TS | MIMICUS_SOK))
        {
            res |= resize_tcpopts(iph, tcph, 11);
            //addo_mss(&tcpopts, tcpo->mss);
            //addo_nop(&tcpopts);
            //addo_scale(&tcpopts, 0);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_ts(&tcpopts, 0, tcpo->ts2);
            //addo_nop(&tcpopts);
            //addo_nop(&tcpopts);
            //addo_sok(&tcpopts);
            write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->scale = 0;
            write_tcp_opt(&tcpopts, OPT_SCALE, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            tcpo->ts1 = 0;
            write_tcp_opt(&tcpopts, OPT_TS, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
            write_tcp_opt(&tcpopts, OPT_SOK, tcpo);
        }
    }
    else
    {
        //printf("SYN\n");
        res |= resize_tcpopts(iph, tcph, 8);
        //addo_mss(&tcpopts, tcpo->mss);
        //addo_nop(&tcpopts);
        //addo_scale(&tcpopts, 1);
        //addo_nop(&tcpopts);
        //addo_nop(&tcpopts);
        //addo_sok(&tcpopts);
        write_tcp_opt(&tcpopts, OPT_MSS, tcpo);
        write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
        tcpo->scale = 1;
        write_tcp_opt(&tcpopts, OPT_SCALE, tcpo);
        write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
        write_tcp_opt(&tcpopts, OPT_NOP, tcpo);
        write_tcp_opt(&tcpopts, OPT_SOK, tcpo);
    }

    //if tcp options were resized, packet length needs to be updated
    *plen = ntohs(iph->tot_len);

    return res;
}

//int mmangle_udp(char *buf, int *plen)
//{
//    return 0;
//}
