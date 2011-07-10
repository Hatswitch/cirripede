
#include <inttypes.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <iostream>
#include <boost/make_shared.hpp>
#include <map>
#include <openssl/rand.h>

static const char rcsid[] =
    "$Id$";

using std::string;
using std::cout;
using std::endl;
using std::map;

using boost::lexical_cast;
using boost::shared_ptr;
using boost::make_shared;

// /* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_totallen;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* IPv6 header */
struct sniff_ipv6 {
        u_char  ip_vhl;                 /* version << 4 */
        u_char  dontcare[3];
        u_short ip_payloadlen;
        u_char  ip_nextheader;
        u_char  dontcare2[33];
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define log cout << __FILE__ << ":" << __LINE__ << ": "

static unsigned long long int g_matchedcount = 0;
static bool g_nomac = false;
static int g_machdrlen = SIZE_ETHERNET;
static unsigned long long int g_syncount = 0;
static unsigned long long int g_synsize = 0;
static unsigned long long int g_443count = 0;
static unsigned long long int g_443size = 0;
static unsigned long long int g_ipv4count = 0;
static unsigned long long int g_ipv6count = 0;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct sniff_tcp *tcp;            /* The TCP header */
    uint32_t pktlen = 0; // whole ip packet len (header+payload)
    int iphdrlen;
    int tcphdrlen;

    /* seems the CAIDA traces have MAC layer removed */
    u_char ip_version = (*(packet + g_machdrlen)) >> 4;

    g_matchedcount += 1;

    if (ip_version == 4) {
        const struct sniff_ip *ip = (struct sniff_ip*)(packet +
                                                       g_machdrlen);
        iphdrlen = IP_HL(ip)*4;
#if 0
        assert(iphdrlen >= 20);
#else
        if (iphdrlen < 20) {
            printf("   * Invalid IP header length: %u bytes ("
                   "matched packet number %llu)\n", iphdrlen, g_matchedcount);
            return;
        }
#endif

        g_ipv4count++;

        assert (ip->ip_p == 6); // tcp
        pktlen += ntohs(ip->ip_totallen);
    }
    else if (ip_version == 6) {
        iphdrlen = 40;
        const struct sniff_ipv6 *ipv6 = (struct sniff_ipv6*)(packet +
                                                             g_machdrlen);

        g_ipv6count++;

        assert (ntohs(ipv6->ip_nextheader) == 6); // tcp
        pktlen += ntohs(ipv6->ip_payloadlen) + 40;
    }
    else {
        printf("   * Invalid IP version %u (matched packet number %llu)\n",
               ip_version, g_matchedcount);
        exit(EXIT_FAILURE);
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + g_machdrlen + iphdrlen);
    tcphdrlen = TH_OFF(tcp)*4;
#if 0
    assert (tcphdrlen >= 20);
#else
    if (tcphdrlen < 20) {
        printf("   * Invalid TCP header length: %u bytes (matched packet number %llu, IP vers %u)\n",
               tcphdrlen, g_matchedcount, ip_version);
        return;
    }
#endif

    if (tcp->th_flags == TH_SYN) {
        g_syncount ++;
        g_synsize += pktlen;
    }

    if (ntohs(tcp->th_dport) == 443) {
        g_443count ++;
        g_443size += pktlen;
    }

    return;
}

int main(int argc, char **argv)
{
    const char *pcapfilepath = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */

    string filter_exp = "tcp";
    struct bpf_program fp;          /* compiled filter program (expression) */
    int opt;
    int long_index;

    struct option long_options[] = {
        {"pcapfilepath", required_argument, 0, 1001},
        {"nomac", no_argument, 0, 1003},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "", long_options, &long_index)) != -1)
    {
        switch (opt) {
        case 0:
            if (long_options[long_index].flag != 0) {
                break;
            }
            cout << "option " << long_options[long_index].name;
            if (optarg) {
                cout << " with arg " << optarg;
            }
            cout << endl;
            break;

        case 1001:
            pcapfilepath = optarg;
            break;

        case 1003:
            g_nomac = true;
            g_machdrlen = 0;
            break;
        }
    }

    assert(pcapfilepath != NULL);

    /* open input pcap file */
    handle = pcap_open_offline(pcapfilepath, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open input pcap file %s: %s\n",
                pcapfilepath, errbuf);
        exit(EXIT_FAILURE);
    }

    filter_exp += " and (tcp[tcpflags] == tcp-syn or dst port 443)";

    memset(&fp, 0, sizeof fp);
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp.c_str(), pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp.c_str(), pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    printf("filter: \"%s\"\n", filter_exp.c_str());

    /* now we can set our callback function */
    pcap_loop(handle, 0, got_packet, NULL);

    printf("\n\ntotal number of matched (and good) packets: %llu "
           "(%.3f M)\n", g_matchedcount,
           ((double)g_matchedcount) / (1024 * 1024));

    printf("\n  ipv4 count: %llu (%.3f M)\n"
           "\n  ipv6 count: %llu (%.3f M)\n",
           g_ipv4count, ((double)g_ipv4count) / (1024 * 1024),
           g_ipv6count, ((double)g_ipv6count) / (1024 * 1024));

    printf("\n\ntotal count and size of matched packets:\n"
           "SYN: %llu, %.3f GB (%llu bytes)\n"
           "443: %llu, %.3f GB (%llu bytes)\n",
           g_syncount, ((double)g_synsize) / (1024 * 1024 * 1024), g_synsize,
           g_443count, ((double)g_443size) / (1024 * 1024 * 1024), g_443size);

    /* cleanup */

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
