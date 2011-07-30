
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
#include <math.h>

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
static int g_machdrlen = SIZE_ETHERNET;
//static unsigned long long int g_syncount = 0;
//static unsigned long long int g_synsize = 0;
static unsigned long long int g_ipv4count = 0;
static unsigned long long int g_ipv6count = 0;
static bool g_count_ipv6 = true;
static uint32_t g_bucketsize = 1;

// map from interarrival-time to count
static map<uint32_t, unsigned long long int> g_iat2count;

// the time of the last arrival
static struct timeval g_lastArrival;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct sniff_tcp *tcp;            /* The TCP header */
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

        if (ip->ip_p != 6) { // tcp
            printf("   * unexpected proto in ipv4 packet: %u ("
                   "matched packet number %llu)\n", ip->ip_p, g_matchedcount);
            return;
        }

        g_ipv4count++;
    }
    else if (ip_version == 6) {
        if (!g_count_ipv6) {
            return;
        }
        iphdrlen = 40;
        const struct sniff_ipv6 *ipv6 = (struct sniff_ipv6*)(packet +
                                                             g_machdrlen);

        if (ntohs(ipv6->ip_nextheader) == 6) { // tcp
            printf("   * unexpected proto in ipv6 packet: %u ("
                   "matched packet number %llu)\n", ntohs(ipv6->ip_nextheader),
                   g_matchedcount);
            return;
        }

        g_ipv6count++;
    }
    else {
        printf("   * Invalid IP version %u (matched packet number %llu)\n",
               ip_version, g_matchedcount);
        return;
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

    assert (tcp->th_flags == TH_SYN);

    if (g_lastArrival.tv_sec == 0 && g_lastArrival.tv_usec == 0) {
        // this is first packet, so only update the g_lastArrival
        g_lastArrival = header->ts;
    }
    else {
        struct timeval elapsedtime;
        struct timeval newtscopy = header->ts;

        if (timercmp(&newtscopy, &g_lastArrival, <)) {
            printf(" * matched packet num %llu has smaller timestamp than "
                   " the last matched packet\n",
                   g_matchedcount);
            // resetting g_lastArrival
            bzero(&g_lastArrival, sizeof g_lastArrival);
            return;
        }

        timersub(&newtscopy, &g_lastArrival, &elapsedtime);

        uint32_t usec;

        if (elapsedtime.tv_sec > 0) {
            // more than 1 sec --> group as 1 second
            usec = 1000000;
        }
        else {
            // if bucketsize = 10, then values 1 -> 10 become 10, 11
            // -> 20 become 20, etc
            usec = g_bucketsize * (int)ceil(((double)elapsedtime.tv_usec) / g_bucketsize);
        }

        g_iat2count[usec] += 1;

        //cout << "usec: " << usec << " count: " << g_iat2count[usec] << endl;
        g_lastArrival = header->ts;
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

    bzero(&g_lastArrival, sizeof g_lastArrival);

    struct option long_options[] = {
        {"pcapfilepath", required_argument, 0, 1001},
        {"no-ipv6", no_argument, 0, 1004},
        {"bucket-size", required_argument, 0, 1005},
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

        case 1004:
            g_count_ipv6 = false;
            break;

        case 1005:
            g_bucketsize = strtol(optarg, NULL, 10);
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

    filter_exp += " and (tcp[tcpflags] == tcp-syn)";

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

    int linktype;
    linktype = pcap_datalink(handle);
    if (linktype == DLT_EN10MB) {
        g_machdrlen = SIZE_ETHERNET;
    }
    else if (linktype == DLT_RAW) {
        g_machdrlen = 0;
    }
    else {
        fprintf(stderr, "pcap datalink type %d not supported\n", linktype);
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, 0, got_packet, NULL);

    printf("Id: %s\n", rcsid);
    printf("pcapfilepath: %s\n", pcapfilepath);
    printf("no-mac: %s\n", g_machdrlen == 0 ? "true" : "false");
    printf("no-ipv6: %s\n", g_count_ipv6 ? "false" : "true");
    printf("bucket-size: %d\n", g_bucketsize);
    printf("filter: \"%s\"\n", filter_exp.c_str());
    printf("\nnumber of bpf-filter-matched packets (though might count packets "
           "we rejected): %llu (%.3f M)\n", g_matchedcount,
           ((double)g_matchedcount) / (1000 * 1000));

    // printf("  ipv4 count: %llu (%.3f M)\n"
    //        "  ipv6 count: %llu (%.3f M)\n",
    //        g_ipv4count, ((double)g_ipv4count) / (1000 * 1000),
    //        g_ipv6count, ((double)g_ipv6count) / (1000 * 1000));

    for (map<uint32_t, unsigned long long>::iterator it = g_iat2count.begin();
         it != g_iat2count.end(); it++)
    {
        printf("interval: %u, count: %llu\n",
               (*it).first, (*it).second);
    }

    /* cleanup */

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
