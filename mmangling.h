#ifndef _MMANGLING_H
#define _MMANGLING_H

#include <stdint.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>

enum tcp_opt_type
{
    OPT_EOL     = 0,
    OPT_NOP     = 1,
    OPT_MSS     = 2,
    OPT_SCALE   = 3,
    OPT_SOK     = 4,
    OPT_TS      = 8,
};

struct tcpoptions
{
    uint8_t o; //bitmask for options present
    uint8_t scale; //window scale value
    uint16_t mss; //max segment size
    uint32_t ts1; //timestamp 1
    uint32_t ts2; //timestamp 2
};

struct tstamp
{
    uint32_t ts1;
    uint32_t ts2;
};

union tcpopt_data
{
    uint8_t scale;
    uint16_t mss;
    struct tstamp ts;
};

/*
 * scans the options of a tcp packet and copies info
 *
 * opts - start of tcp options
 * olen - length of options
 *
 * returns tcpoptions struct on heap, NULL if error
 */
struct tcpoptions* scan_tcpopts(char *opts, int olen);
void addo_nop(void **tcpop);
void addo_eol(void **tcpop);
void addo_sok(void **tcpop);
void addo_mss(void **tcpop, uint16_t mssv);
void addo_scale(void **tcpop, uint8_t scale);
void addo_ts(void **tcpop, uint32_t ts1, uint32_t ts2);

/*
 * Writes a tcp option to the specified area
 *
 * tcpop - the area to write the option
 * otype - type of option
 * todat - data for scale/mss/timestamp option
 *
 * returns 0 if no option written, otherwise MIMICUS_TCP_CS
 */
int write_tcp_opt(void **tcpop, enum tcp_opt_type otype, struct tcpoptions *to);

/*
 * Resizes the tcp header's space for options
 *
 * offs - the new data offset for the tcp header.
 *        translates to ((offs * 4) - 20) bytes for options
 * returns 0 if nothing changed, else (MIMICUS_IP_CS | MIMICUS_TCP_CS)
 */
int resize_tcpopts(struct iphdr *iph, struct tcphdr *tcph, uint8_t offs);

/*
 * (Re)calculates ip checksum
 *
 * iph - ip header
 */
void ip_checksum(struct iphdr *iph);

/*
 * (Re)calculates tcp checksum
 *
 * iph - ip header
 */
void tcp_checksum(struct iphdr *iph);

/*
 * (Re)calculates udp checksum
 *
 * iph - ip header
 */
void udp_checksum(struct iphdr *iph);

/*
 * set the window size of a tcp packet
 *
 * tcph - tcp header
 * sz - window size
 * returns MIMICUS_TCP_CS
 */
int set_tcp_winsize(struct tcphdr *tcph, uint16_t sz);

/*
 * set the don't fragment bit a tcp packet
 *
 * iph - ip header
 * f - flag setting bit, 0 = off , non-zero = on
 * returns 0 if no change, otherwise MIMICUS_IP_CS
 */
int set_df(struct iphdr *iph, uint8_t f);

/*
 * set the ipid to a non-zero number
 *
 * iph - ip header
 * returns 0 if unchanged, otherwise MIMICUS_IP_CS
 */
int set_ipid_nonzero(struct iphdr *iph);

#endif //_MMANGLING_H
