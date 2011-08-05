/* this program reads a pcap file, places the registration signal in
 * the initial sequence numbers but otherwise does not touch other
 * content/packets.
 */



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
#include <set>
#include "common.hpp"
#include <openssl/rand.h>
#include <math.h>

extern "C" {
#include "curve25519-20050915/curve25519.h"
}

static const char rcsid[] =
    "$Id$";

using std::string;
using std::cout;
using std::endl;
using std::map;
using std::set;

using boost::lexical_cast;
using boost::shared_ptr;
using boost::make_shared;

#define CURVE25519_KEYSIZE (32)

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

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

static unsigned long long g_count = 0;
static u_char g_rspubkey[CURVE25519_KEYSIZE] = {0};
static pcap_dumper_t* g_dumperhandle = NULL;
static int g_machdrlen = SIZE_ETHERNET;
static bool g_verbose = false;
static unsigned long long g_completeSignalCount = 0; // number of
						     // whole/complete
						     // signals added

static uint32_t g_bytesPerISN = 0;
static uint32_t g_numRequiredPkts = 0;

// use one single key (and thus encrypted signals etc) for all clients
// to improve performance significantly
static bool g_useOneKey = false;
static u_char g_signal[CURVE25519_KEYSIZE + 4] = {0};
static bool g_oncePerClient = false;

struct Client {
    u_char _signal[CURVE25519_KEYSIZE + 4]; // pubkey, then 4 bytes
                                            // for the encryption of
                                            // "register"

    u_char _offset; // current byte-offset within _signal to copy into
                    // TCP SYN ISN, thus if this is < sizeof(_signal),
                    // then still needs to copy more
};

typedef struct Client Client_t;

// key is the src/client ip address (network-byte-order)
map<uint32_t, Client_t> g_ip2Clients;

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const char *header /* optional */,
                     const unsigned char *payload, int len, int offset,
                     const bool hexonly=true)
{

    int i;
    int gap;
    const unsigned char *ch;

    if (header) {
        printf("%s:\n", header);
    }
    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (((i + 1) % 4) == 0)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }

    if (!hexonly) {
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
        if (((i + 1) % 4) == 0)
            printf(" ");
    }
    }

    printf("\n");

    return;
}

void gensecretkey(unsigned char secret[CURVE25519_KEYSIZE])
{
    int i = 0;
    for (; i < CURVE25519_KEYSIZE; i++) {
        if (1 != RAND_bytes(secret + i, 1)) {
            puts("error generating random bytes for secret key");
            exit(-1);
        }
    }
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
}

void computepublickey(unsigned char pub[CURVE25519_KEYSIZE],
                      const unsigned char secret[CURVE25519_KEYSIZE])
{
    static const unsigned char basepoint[CURVE25519_KEYSIZE] = {9};
    curve25519(pub,secret,basepoint);
}

int
getciphertext(const u_char *sharedcurvekey /* [CURVE25519_KEYSIZE] */,
              /* used for registering */
              u_char *rsciphertext /*[4]*/
              /* used to signal to proxy */
#if 0
              u_char *proxysynciphertext /*[4]*/,
              u_char *proxyackciphertext /*[4]*/
#endif
    )
{
    int err = 0;
    int retval = 0;
    static const char str[] = "register";
    BIO *ciphertextbio = NULL;
    BIO *benc = NULL;
    /// generate key and iv for cipher
    u_char cipherkey[EVP_MAX_KEY_LENGTH] = {0};
    u_char cipheriv[EVP_MAX_IV_LENGTH] = {0};

    // data to derive cipher key/iv
    u_char kdf_data[CURVE25519_KEYSIZE + 1] = {0};
    // use the shared curve25519 key
    memcpy(kdf_data, sharedcurvekey, CURVE25519_KEYSIZE);

    // the last byte is "1" to derive the aes key
    kdf_data[(sizeof kdf_data) - 1] = '1';

    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int keylen = EVP_BytesToKey(
        cipher, EVP_sha1(), NULL, kdf_data, sizeof kdf_data, 1,
        cipherkey, cipheriv);
    bail_require(keylen == cipher->key_len);

    benc = BIO_new(BIO_f_cipher());
    bail_null(benc);

    BIO_set_cipher(benc, cipher, cipherkey, cipheriv, 1);

    ciphertextbio = BIO_new(BIO_s_mem());
    bail_null(ciphertextbio);

    bail_require(BIO_push(benc, ciphertextbio) == benc);

    retval = BIO_write(benc, str, strlen(str));
    bail_require(retval == strlen(str));
    bail_require(1 == BIO_flush(benc)); // need to flush

    // read out the first 4 bytes of the regciphertext
    retval = BIO_read(ciphertextbio, rsciphertext, 4);
    bail_require(retval == 4);

#if 0
    //////////////////////////
    // now get the cipher text for signalling the proxy and the expected
    // response

    retval = BIO_write(benc, syn, strlen(syn));
    bail_require(retval == strlen(syn));
    bail_require(1 == BIO_flush(benc));

    retval = BIO_read(ciphertextbio,
                      proxysynciphertext, 4);
    bail_require(retval == 4);

    retval = BIO_write(benc, ack, strlen(ack));
    bail_require(retval == strlen(ack));
    bail_require(1 == BIO_flush(benc));

    retval = BIO_read(ciphertextbio,
                      proxyackciphertext, 4);
    bail_require(retval == 4);
#endif

bail:
    openssl_safe_free(BIO, benc);
    openssl_safe_free(BIO, ciphertextbio);
    return err;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    int iphdrlen;
    int tcphdrlen;
    static char ipaddrstr[INET_ADDRSTRLEN];
    static set<uint32_t> clientsHaveReg; // clients who have registered

    const u_char ip_version = (*(packet + g_machdrlen)) >> 4;

    g_count ++;

    if (ip_version != 4) {
        goto bail;
    }

    ip = (struct sniff_ip*)(packet + g_machdrlen);
    iphdrlen = IP_HL(ip)*4;

    if (ip->ip_p != IPPROTO_TCP || iphdrlen < 20) {
        goto bail;
    }
    
    /*
     *  OK, this packet is TCP.
     */
    
    tcp = (struct sniff_tcp*)(packet + g_machdrlen + iphdrlen);
    tcphdrlen = TH_OFF(tcp)*4;
    if (tcphdrlen < 20 || tcp->th_flags != TH_SYN) {
        goto bail;
    }

    if (g_oncePerClient &&
        clientsHaveReg.end() != clientsHaveReg.find(ip->ip_src.s_addr)) {
        // client has registered once -> skip
        goto bail;
    }

#define COPY_INTO_ISN(tcpISNPtr, signal, offset, numBytesPerISN)        \
    do {                                                                \
        memcpy((u_char*)(tcpISNPtr) + 0, (signal) + (offset), (numBytesPerISN)); \
        (offset) += (numBytesPerISN);                                   \
    }                                                                   \
    while (0)

    if (Common::inMap(g_ip2Clients, ip->ip_src.s_addr)) {
        Client_t& client = g_ip2Clients[ip->ip_src.s_addr];
        if (client._offset < sizeof (client._signal)) {
            if (g_useOneKey) {
                COPY_INTO_ISN(&(tcp->th_seq), g_signal,
                              client._offset, g_bytesPerISN);
            }
            else {
                COPY_INTO_ISN(&(tcp->th_seq), client._signal,
                              client._offset, g_bytesPerISN);
            }
        }

        if (client._offset == sizeof (client._signal)) {
            if (g_verbose) {
                bail_null(inet_ntop(AF_INET, &ip->ip_src, ipaddrstr, sizeof ipaddrstr));
                printf("client %s (%u) completed signal\n", ipaddrstr, ip->ip_src.s_addr);
                print_hex_ascii_line("pubkey+signal",
                                     g_useOneKey ? g_signal : client._signal,
                                     sizeof client._signal, 0);
                printf("\n");
            }
            // removing client from map, so it will be considered a
            // fresh client later
            g_ip2Clients.erase(ip->ip_src.s_addr);
            g_completeSignalCount ++;
            if (g_oncePerClient) {
                // remember that we have registered this client
                clientsHaveReg.insert(ip->ip_src.s_addr);
            }
        }
    }
    else {
        // generate curve pub key and client struct for this newly
        // seen client src address

        Client_t client;
        client._offset = 0;

        if (g_useOneKey) {
            COPY_INTO_ISN(&(tcp->th_seq), g_signal,
                          client._offset, g_bytesPerISN);
        }
        else {
            u_char seckey[CURVE25519_KEYSIZE];
            gensecretkey(seckey);
            computepublickey(client._signal, seckey);
            u_char sharedkey[CURVE25519_KEYSIZE];
            curve25519(sharedkey, seckey, g_rspubkey);

            // u_char proxysynciphertext[4] = {0};
            // u_char proxyackciphertext[4] = {0};

            bail_error(getciphertext(sharedkey, client._signal + CURVE25519_KEYSIZE));

            COPY_INTO_ISN(&(tcp->th_seq), client._signal,
                          client._offset, g_bytesPerISN);
        }

        g_ip2Clients[ip->ip_src.s_addr] = client;
    }

bail:
    // we dump the packet no matter what
    pcap_dump((u_char*)g_dumperhandle, header, packet);

    return;
}

int main(int argc, char **argv)
{
    int err = 1;
    const char *rspubkeypath = NULL;
    const char *inpcapfilepath = NULL;
    const char *outpcapfilepath = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle = NULL;             /* packet capture handle */

    int opt;
    int long_index;
    u_short port = 0;
    BIO *rs_curve_pubkey_filebio = NULL;

    struct option long_options[] = {
        {"inpcapfilepath", required_argument, 0, 1001},
        {"rspubkeypath", required_argument, 0, 1002},
        {"outpcapfilepath", required_argument, 0, 1003},
        {"verbose", no_argument, 0, 1005},
        {"use-one-key", no_argument, 0, 1006},
        {"bytesPerISN", required_argument, 0, 1007}, // either 3 or 4
        {"oncePerClient", no_argument, 0, 1008},
        {0, 0, 0, 0},
    };

    printf("Revision: %s\n\n", rcsid);
    for (int i = 0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n\n");

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
            port = strtod(optarg, NULL);
            break;

        case 1001:
            inpcapfilepath = optarg;
            break;

        case 1002:
            rspubkeypath = optarg;
            break;

        case 1003:
            outpcapfilepath = optarg;
            break;

        case 1005:
            g_verbose = true;
            break;

        case 1006:
            g_useOneKey = true;
            break;

        case 1007:
            g_bytesPerISN = strtod(optarg, NULL);
            break;

        case 1008:
            g_oncePerClient = true;
            break;

        default:
            exit(-1);
            break;
        }
    }

    bail_require_msg(g_bytesPerISN == 3 || g_bytesPerISN == 4,
                     "must specify --bytesPerISN with 3 or 4");
    g_numRequiredPkts = (uint8_t)ceil(((double)(CURVE25519_KEYSIZE + 4)) /
                                      g_bytesPerISN);

    assert(inpcapfilepath != NULL);
    assert(outpcapfilepath != NULL);
    assert(rspubkeypath != NULL);

    rs_curve_pubkey_filebio = BIO_new_file(rspubkeypath, "rb");
    assert(rs_curve_pubkey_filebio != NULL);

    bail_require_msg(
        sizeof g_rspubkey == BIO_read(
            rs_curve_pubkey_filebio, g_rspubkey, sizeof g_rspubkey),
        "error reading rs curve pub key");

    /* open input pcap file */
    handle = pcap_open_offline(inpcapfilepath, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open input pcap file %s: %s\n",
                inpcapfilepath, errbuf);
        exit(EXIT_FAILURE);
    }

    /* open output pcap file */
    g_dumperhandle = pcap_dump_open(handle, outpcapfilepath);
    assert(g_dumperhandle != NULL);

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

    if (g_useOneKey) {
        assert(sizeof g_signal == sizeof ((Client_t*)NULL)->_signal);
        u_char seckey[CURVE25519_KEYSIZE];
        u_char sharedkey[CURVE25519_KEYSIZE];

        gensecretkey(seckey);
        computepublickey(g_signal, seckey);
        curve25519(sharedkey, seckey, g_rspubkey);
        bail_error(getciphertext(sharedkey, g_signal + CURVE25519_KEYSIZE));
    }

    /* now we can set our callback function */
    pcap_loop(handle, 0, got_packet, NULL);

    /* cleanup */
    printf("\nTotal packet count: %llu\n", g_count);
    printf("\nComplete signals count: %llu\n", g_completeSignalCount);

    err = 0;

bail:
    openssl_safe_free(BIO, rs_curve_pubkey_filebio);
    if (handle) {
        pcap_close(handle);
    }
    if (g_dumperhandle) {
        pcap_dump_close(g_dumperhandle);
    }
    return err;
}
