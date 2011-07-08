

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
// #define SIZE_ETHERNET 14

// /* Ethernet addresses are 6 bytes */
// #define ETHER_ADDR_LEN	6

// /* Ethernet header */
// struct sniff_ethernet {
//         u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
//         u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
//         u_short ether_type;                     /* IP? ARP? RARP? etc */
// };

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
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

static u_short g_dstport = 0;
static bool g_synonly = false;
static uint64_t g_matchedcount = 0;
static uint64_t g_matchedAndGood_size = 0;
static uint64_t g_matchedAndGood_count = 0;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    int size_ip;
    int size_tcp;

    g_matchedcount += 1;

    /* seems the CAIDA traces have MAC layer removed */
    ip = (struct sniff_ip*)(packet);
    size_ip = IP_HL(ip)*4;
#if 0
    assert(size_ip >= 20);
#else
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes ("
               "matched packet number %lu)\n", size_ip, g_matchedcount);
        return;
    }
#endif

    if (IP_V(ip) != 4) {
        printf("ip version %u packet not supported (matched packet number %lu)\n", IP_V(ip), g_matchedcount);
	return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + size_ip);
    size_tcp = TH_OFF(tcp)*4;
#if 0
    assert (size_tcp >= 20);
#else
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes (matched packet number %lu)\n", size_tcp, g_matchedcount);
        return;
    }
#endif

    if (g_synonly) {
        assert(tcp->th_flags == TH_SYN);
    }

    if (g_dstport > 0) {
        assert (ntohs(tcp->th_dport) == g_dstport);
    }

    g_matchedAndGood_count += 1;
    g_matchedAndGood_size += ntohs(ip->ip_len);

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
        {"dstport", required_argument, 0, 1000},
        {"pcapfilepath", required_argument, 0, 1001},
        {"synonly", no_argument, 0, 1002},
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

        case 1000:
            g_dstport = strtod(optarg, NULL);
            break;

        case 1001:
            pcapfilepath = optarg;
            break;

        case 1002:
            g_synonly = true;
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

    if (g_dstport > 0) {
        filter_exp += " and dst port " + lexical_cast<string>(g_dstport);
    }

    if (g_synonly) {
        filter_exp += " and tcp[tcpflags] == tcp-syn";
    }

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

    printf("syn-only: %s\n", g_synonly ? "true" : "false");
    if (g_dstport > 0) {
        printf("dst port: %u\n", g_dstport);
    }
    else {
        printf("port: all ports\n");
    }
    printf("filter: \"%s\"\n", filter_exp.c_str());

    /* now we can set our callback function */
    pcap_loop(handle, 0, got_packet, NULL);

    printf("\n\ntotal number of matched (and good) packets: %llu\n", g_matchedAndGood_count);

    printf("\n\ntotal size of matched (and good) packets:\n"
           "%llu bytes\n"
           "%.2f MB\n"
           "%.2f GB\n",
           g_matchedAndGood_size,
           ((double)g_matchedAndGood_size) / (1024 * 1024),
           ((double)g_matchedAndGood_size) / (1024 * 1024 * 1024));

    /* cleanup */

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
