#include "mimicus.h"
//#include "mmangling.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <string.h>
#include <dlfcn.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define MANGLE_FUNC "mmangle_ip"

static int32_t lflag = 1;

extern char *optarg;
extern int optind, opterr, optopt;
static int (*mangler)(char *buf, int *plen);

struct mopts
{
    int qn;
    char libname[256];
};

int mcb(struct nfq_q_handle *nqh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData)
{
    int id = 0;
    int plen = 0;
    int rtn = 0;
    unsigned char *pdata;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(pkt);
    if (ph)
    {
        id = ntohl(ph->packet_id);
        plen = nfq_get_payload(pkt,&pdata);
        if ((plen > 0) && (plen <= MBUF_SZ))
        {
            rtn = mangler(pdata, &plen);
        }
    }

    if (rtn == 0) //nothing changed, no need to send updated packet info
    {
        rtn = nfq_set_verdict(nqh, id, NF_ACCEPT, 0, NULL);
    }
    else
    {
        rtn = nfq_set_verdict(nqh, id, NF_ACCEPT, plen, pdata);
    }

    return rtn;
}

void sighandler(int sig)
{
    if (sig == SIGINT)
    {
        lflag = 0;
    }
}

struct mopts* parse_args(int argc, char **argv)
{
    struct mopts* mo;
    char go = 0;

    if (argc != 5) return NULL;

    mo = calloc(1, sizeof(struct mopts));

    while ((go = getopt(argc, argv, "q:m:")) != -1)
    {
        if (go == 'q')
        {
            mo->qn = atoi(optarg);
        }
        else if (go == 'm')
        {
            strncpy((char *)&mo->libname, optarg, 255);
        }
    }
    //printf("Queue: %d Lib: %s\n", mo->qn, mo->libname);
    return mo;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, res;
    struct mopts *mo;
    char *pbuf;
    void *lib;

    signal(SIGINT,sighandler);

    mo = parse_args(argc, argv);
    if (!mo)
    {
        printf("mimicus -q QUEUE -m MODULE\n");
        printf("ie: mimicus -q 0 -m ./libwinxp.so\n");
        exit(1);
    }

    lib = dlopen(mo->libname, RTLD_LAZY);
    if (!lib)
    {
        printf("error loading library libwinxp.so: %s\n", dlerror());
        exit(1);
    }

    mangler = dlsym(lib, MANGLE_FUNC);
    if (!mangler)
    {
        printf("Error loading mangle function from libwinxp.so: %s\n", dlerror());
        exit(1);
    }

    pbuf = calloc(1, MBUF_SZ);
    if (!pbuf)
    {
        printf("calloc error\n");
        exit(1);
    }

    h = nfq_open();
    if (!h)
    {
        printf("error calling nfq_open\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        printf("error calling nfq_unbind_pf\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        printf("error calling nfq_bind_pf\n");
        exit(1);
    }

    if ((qh = nfq_create_queue(h, mo->qn, &mcb, NULL)) == NULL)
    {
        printf("error calling nfq_create_q\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        printf("error calling nfq_set_mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    while(lflag)
    {
        res = recv(fd, pbuf, MBUF_SZ, 0);
        if (res >= 0)
        {
            nfq_handle_packet(h, pbuf, res);
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    free(pbuf);
    free(mo);

    return 0;
}

