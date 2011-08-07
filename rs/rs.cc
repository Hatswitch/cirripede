
/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression           Description
 * ----------           -----------
 * ip                   Capture all IP packets.
 * tcp                  Capture only TCP packets.
 * tcp port 80          Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3     Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME        "sniffex"
#define APP_DESC        "Sniffer example using libpcap"
#define APP_COPYRIGHT   "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <signal.h>
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
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <getopt.h>
#include <sstream>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <iostream>
#include "ThreadSafeQueue.hpp"
#include <boost/make_shared.hpp>
#include <map>
#include <vector>
#include "common.hpp"
#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/layout.h>
#include <log4cxx/patternlayout.h>
#include <sys/prctl.h>

extern "C" {
#include "curve25519-20050915/curve25519.h"
}

static const char rcsid[] =
    "$Id$";

using std::string;
using std::cout;
using std::endl;
using std::map;
using std::vector;
using std::ostream;
using std::stringstream;

using boost::lexical_cast;
using boost::shared_ptr;
using boost::make_shared;
using boost::posix_time::time_duration;

using namespace log4cxx;

static LoggerPtr g_logger = log4cxx::Logger::getRootLogger();

// we only need upto the tcp sequence number
#define SNAP_LEN (SIZE_ETHERNET + 60 + 2)

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

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

#define MYLOG(x) LOG4CXX_INFO(g_logger, x)
#define MYLOGWARN(x) LOG4CXX_WARN(g_logger, x)
#define MYLOGINFO(x) LOG4CXX_INFO(g_logger, x)
#define MYLOGDEBUG(x) LOG4CXX_DEBUG(g_logger, x)

#define CURVE25519_KEYSIZE (32)

/* this part is necessary for openssl to be thread-safe. copied from
 * openssl's mttest.c
 */

static pthread_mutex_t *lock_cs;
static long *lock_count;

unsigned long pthreads_thread_id(void)
{
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}

void pthreads_locking_callback(int mode, int type, const char *file,
                               int line)
{
#ifdef undef
	fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
            CRYPTO_thread_id(),
            (mode&CRYPTO_LOCK)?"l":"u",
            (type&CRYPTO_READ)?"r":"w",file,line);
#endif
/*
  if (CRYPTO_LOCK_SSL_CERT == type)
  fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
  CRYPTO_thread_id(),
  mode,file,line);
*/
	if (mode & CRYPTO_LOCK)
    {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
    }
	else
    {
		pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void thread_setup(void)
{
	int i;

	lock_cs=(pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count=(long *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i=0; i<CRYPTO_num_locks(); i++)
    {
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL);
    }

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	fprintf(stderr,"cleanup\n");
	for (i=0; i<CRYPTO_num_locks(); i++)
    {
		pthread_mutex_destroy(&(lock_cs[i]));
		fprintf(stderr,"%8ld:%s\n",lock_count[i],
                CRYPTO_get_lock_name(i));
    }
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);

	fprintf(stderr,"done cleanup\n");
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const char *header /* optional */,
                     const unsigned char *payload, int len, int offset,
                     ostream* os = NULL,
                     const bool hexonly=true)
{

    int i;
    int gap;
    const unsigned char *ch;

    if (header) {
        if (os) {
            (*os) << boost::format("%s:\n") % header;
        }
        else {
            printf("%s:\n", header);
        }
    }

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (os) {
            *os << boost::format("%02x") % (int)(*ch);
        }
        else {
            printf("%02x", *ch);
        }
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (((i + 1) % 4) == 0) {
            if (os) {
                *os << (" ");
            }
            else {
                printf(" ");
            }
        }
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8) {
        if (os) {
            *os << " ";
        }
        else {
            printf(" ");
        }
    }

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            if (os) {
                *os << "   ";
            }
            else {
                printf("   ");
            }
        }
    }

    if (!hexonly) {
        if (os) {
            *os << ("   ");
        }
        else {
            printf("   ");
        }

        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
            if (isprint(*ch)) {
                if (os) {
                    *os << boost::format("%c") % (*ch);
                }
                else {
                    printf("%c", *ch);
                }
            }
            else {
                if (os) {
                    *os << (".");
                }
                else {
                    printf(".");
                }
            }
            ch++;
            if (((i + 1) % 4) == 0) {
                if (os) {
                    *os << (" ");
                }
                else {
                    printf(" ");
                }
            }
        }
    }

    printf("\n");

    return;
}


class SynPacket_t {
public:
    SynPacket_t(const u_long& ip_src, const u_char *tcp_seq)
        : _ip_src(ip_src)
    {
        memcpy(_tcp_seq, tcp_seq, sizeof _tcp_seq);
    }

    const u_long _ip_src;
    u_char _tcp_seq[4];
};

typedef enum  {
    CS_ST_PENDING,
    CS_ST_REGISTERED,
} client_state_t;

class ClientState_t {
public:
    ClientState_t()
        : _state(CS_ST_PENDING), _pktcount(0),
          _lastSeen(time(NULL)), _regTime(0) {}

    u_char _signal[CURVE25519_KEYSIZE + 4]; // pubkey + ciphertext
    client_state_t _state;
    u_short _pktcount; // for registration purpose
    time_t _lastSeen; // time of last SYN packet seen
    time_t _regTime; // time when registration succeeds
};


static u_char g_myseckey[CURVE25519_KEYSIZE] = {0};
static int g_proxyctlsocket = -1;
static struct sockaddr_in g_proxyaddr;
static int g_drCtlSocket = -1;
static struct sockaddr_in g_drAddr;
bool g_verbose = false;
bool g_dont_cmp_ciphertext = false;
bool g_hardcode_sharedkey = false;
static u_char g_hardcoded_sharedkey[CURVE25519_KEYSIZE] = {0};
static unsigned long long g_pktcount = 0;
static vector<boost::thread *> g_handlerthreads;
static uint16_t g_validationInterval = 0;
static uint32_t g_bytesPerISN = 0;
static uint32_t g_numRequiredPkts = 0;
static bool g_terminate = false;

static uint32_t g_ipmask = 0;

#define ISPOWEROF2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#define MASK_IP(ip) ((ip) & g_ipmask)

// map from masked IP address to the syn packet queue
static map<uint32_t, shared_ptr<ThreadSafeQueue<shared_ptr<SynPacket_t> > > > g_SYNqueues;

static time_duration g_garbagecollectioninterval = boost::posix_time::seconds(0);


int
encrypt(const EVP_CIPHER *cipher,
        const u_char cipherkey[EVP_MAX_KEY_LENGTH],
        const u_char cipheriv[EVP_MAX_IV_LENGTH],
        const u_char *cleartext,
        const int cleartextlen,
        u_char *ciphertext,
        const int ciphertextlen
    )
{
    int err = 0;
    int retval = 0;
    BIO *ciphertextbio = NULL;
    BIO *benc = NULL;

    bail_require(ciphertextlen <= cleartextlen);

    benc = BIO_new(BIO_f_cipher());
    bail_null(benc);

    BIO_set_cipher(benc, cipher, cipherkey, cipheriv, 1);

    ciphertextbio = BIO_new(BIO_s_mem());
    bail_null(ciphertextbio);

    bail_require(BIO_push(benc, ciphertextbio) == benc);

    retval = BIO_write(benc, cleartext, cleartextlen);
    bail_require(retval == cleartextlen);
    bail_require(1 == BIO_flush(benc)); // need to flush

    // read out the regciphertext
    retval = BIO_read(ciphertextbio, ciphertext, ciphertextlen);
    bail_require(retval == ciphertextlen);

bail:
    openssl_safe_free(BIO, benc);
    openssl_safe_free(BIO, ciphertextbio);
    return err;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_usage(void);

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    /* declare pointers to packet headers */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    shared_ptr<SynPacket_t> synpkt;
    int size_ip;
    int size_tcp;
    
    g_pktcount ++;

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    bail_require_msg(ip->ip_p == IPPROTO_TCP, "getting non-TCP packets");
    
    /*
     *  OK, this packet is TCP.
     */
    
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    bail_require_msg(tcp->th_flags == TH_SYN, "getting non-SYN packets");

    synpkt = make_shared<SynPacket_t>(ip->ip_src.s_addr, (u_char*)&(tcp->th_seq));

#if 0
    uint32_t _ip;
    _ip = ip->ip_src.s_addr;
    char addrstr[30];
    MYLOGINFO("  got pkt from client "
	      << inet_ntop(AF_INET, &_ip, addrstr, INET_ADDRSTRLEN)
	      << " (" << _ip << ")");
#endif

    // put it into the appropriate queue
    g_SYNqueues[ MASK_IP(ip->ip_src.s_addr) ]->put(synpkt);

bail:
    return;
}

/* XXX/TODO: currently not re-entrant */
static void
notifyProxy(const uint32_t& src_ip,
            const u_char *kdf_data,
            const int& kdf_data_len)
{
    static const int max_kdf_data_len = 64; // arbitrary
    int msglen = 4 + kdf_data_len;
    uint32_t ip = htonl(src_ip);

    bail_require(g_proxyctlsocket > -1);
    bail_require(kdf_data_len <= max_kdf_data_len);

    /* 4 for src ip */
    static u_char msg[4 + max_kdf_data_len];

    memcpy(msg + 0, &ip, 4);
    memcpy(msg + 4, kdf_data, kdf_data_len);

    /* best effort, no guarantee */
    bail_require(
        msglen == sendto(g_proxyctlsocket, msg, msglen, MSG_DONTWAIT,
                         (struct sockaddr*)&g_proxyaddr, sizeof g_proxyaddr));
bail:
    return;
}

static void
notifyDR(const uint32_t& src_ip)
{
    int msglen = 4;
    uint32_t ip = htonl(src_ip);

    bail_require(g_drCtlSocket > -1);

    /* 4 for src ip */
    static u_char msg[4];

    memcpy(msg + 0, &ip, 4);

    /* best effort, no guarantee */
    bail_require(
        msglen == sendto(g_drCtlSocket, msg, msglen, MSG_DONTWAIT,
                         (struct sockaddr*)&g_drAddr, sizeof g_drAddr));
bail:
    return;
}

static const EVP_CIPHER *g_signallingcipher = EVP_aes_128_cbc();
static const u_char g_register_str[] = "register";
#define REGISTER_STRLEN ((sizeof g_register_str) - 1)


static void
collectGarbage(map<uint32_t, shared_ptr<ClientState_t> >& clients,
               const time_t& now,
               unsigned long long& numClientsGarbageCollected)
{
    // dont reset numClientsGarbageCollected

    // loop thru the g_clients
//    MYLOGINFO("starting garbage collection");
    map<uint32_t, shared_ptr<ClientState_t> >::iterator cit = clients.begin();
    while (cit != clients.end()) {
        const shared_ptr<ClientState_t>& cs = cit->second;
        if (cs->_state == CS_ST_PENDING && (now > (cs->_lastSeen + (int)g_validationInterval))) {
#ifdef DOLOGGING
            const uint32_t ip = cit->first;
            char tmp[INET_ADDRSTRLEN];
            MYLOGINFO("  remove client "
                      << inet_ntop(AF_INET, &ip, tmp, INET_ADDRSTRLEN)
                      << " (" << ip << ")");
#endif
            clients.erase(cit++);
            numClientsGarbageCollected++;
        }
        else {
            ++cit;
        }
    }
//    MYLOGINFO("done garbage collection");
    return;
}

void
handleSynPackets(const string& threadname,
                 shared_ptr<ThreadSafeQueue<shared_ptr<SynPacket_t> > > synpackets)
{
    /* using shared_ptr here for the valueof the map here is not a
     * must. just whatever performs better.
     */
    map<uint32_t, shared_ptr<ClientState_t> > clients;
    time_t lastGarbageCollection = time(NULL);
    char addrstr[INET_ADDRSTRLEN];
    static const time_duration timeout = boost::posix_time::seconds(5); // 5 is arbitrary

    // statistics
    unsigned long long pktCount = 0; // num of pkts handled here
    unsigned long long regCount = 0; // num of successful registrations
    unsigned long long cryptoCount = 0; // num of times we need to do crypto ops
    unsigned long long numClientsGarbageCollected = 0; // cumulative

    assert (threadname.length() < 16);
    assert (0 == prctl(PR_SET_NAME, threadname.c_str(), 0,0,0));

    MYLOG("thread name " << threadname);

    while (true) {
        // accessing g_terminate un-thread-safely, but this should be
        // ok for now because we're assuming g_terminate is set to
        // true only when we receive a signal, when experiment is
        // done.
        if (g_terminate) {
            MYLOGINFO(threadname << ": pktCount = " << pktCount);
            MYLOGINFO(threadname << ": cryptoCount = " << cryptoCount);
            MYLOGINFO(threadname << ": numClientsGarbageCollected = " << numClientsGarbageCollected);
            MYLOGINFO(threadname << ": regCount = " << regCount);
            return;
        }

        time_t now = time(NULL);
        if (now > (lastGarbageCollection + g_garbagecollectioninterval.total_seconds())) {
            lastGarbageCollection = now;
            collectGarbage(clients, now, numClientsGarbageCollected);
        }

        shared_ptr<SynPacket_t> synpkt;
        if (!synpackets->get_with_timeout(timeout, synpkt)) {
            continue;
        }

        pktCount++;

        // put it in the appropriate table entry
        const uint32_t ip = synpkt->_ip_src;
        shared_ptr<ClientState_t> cs;
        if (Common::inMap(clients, ip)) {
            cs = clients[ip];
        }
        else {
            cs = make_shared<ClientState_t>();
            // put it into the map
            clients[ip] = cs;
            if (g_verbose) {
                MYLOGINFO("  new pending client "
                          << inet_ntop(AF_INET, &ip, addrstr, INET_ADDRSTRLEN)
                          << " (" << ip << ")");
                MYLOGINFO("new map size: " << clients.size());
            }
        }

        ///// at this point, cs is a valid entry in the map /////

        now = time(NULL);
        cs->_lastSeen = now;

        // increment first
        cs->_pktcount += 1;

        memcpy(cs->_signal + ((cs->_pktcount - 1) * g_bytesPerISN),
               synpkt->_tcp_seq, g_bytesPerISN);

        if (cs->_pktcount == g_numRequiredPkts) {
            // we have enough packets --> detect signal
            u_char sharedkey[CURVE25519_KEYSIZE] = {0};
            curve25519(sharedkey, g_myseckey, cs->_signal);

            u_char kdf_data[(sizeof sharedkey) + 1];
            memcpy(kdf_data, g_hardcode_sharedkey ? g_hardcoded_sharedkey : sharedkey, sizeof sharedkey);
            kdf_data[(sizeof kdf_data) - 1] = '1'; // '1' for signalling

            u_char cipherkey[EVP_MAX_KEY_LENGTH] = {0};
            u_char cipheriv[EVP_MAX_IV_LENGTH] = {0};

            int retval = EVP_BytesToKey(
                g_signallingcipher, EVP_sha1(), NULL, kdf_data, sizeof kdf_data, 1,
                cipherkey, cipheriv);
            bail_require(retval == g_signallingcipher->key_len);

            u_char rsciphertext[4] = {0};
            bail_error(encrypt(g_signallingcipher, cipherkey, cipheriv,
                               g_register_str, REGISTER_STRLEN,
                               rsciphertext, sizeof rsciphertext));

            cryptoCount ++;

            if (g_verbose) {
                print_hex_ascii_line("clientkey", cs->_signal,
                                     CURVE25519_KEYSIZE, 0);
                if (!g_hardcode_sharedkey) {
                    print_hex_ascii_line("sharedkey", sharedkey,
                                         sizeof sharedkey, 0);
                }
                print_hex_ascii_line("cipherkey", cipherkey,
                                     sizeof cipherkey, 0);
                print_hex_ascii_line("cipheriv ", cipheriv,
                                     sizeof cipheriv, 0);
                print_hex_ascii_line("expect esignal", rsciphertext,
                                     sizeof rsciphertext, 0);
                print_hex_ascii_line("actual esignal", cs->_signal + CURVE25519_KEYSIZE,
                                     4, 0);
            }

            // reset pkt count
            cs->_pktcount = 0;

#if 0
            stringstream ss;
            print_hex_ascii_line("pubkey+signal", cs->_signal, sizeof (cs->_signal), 0, &ss);
#endif

            /* if g_dont_cmp_ciphertext is true, then we just accept
             * no matter what.
             */
            if (g_dont_cmp_ciphertext || 0 == memcmp(rsciphertext, cs->_signal + CURVE25519_KEYSIZE, 4)) {
                regCount++;
                cs->_regTime = now;

                if (g_verbose) {
                    char timestr[30];
                    MYLOGINFO("   client "
                              << inet_ntop(AF_INET, &ip, addrstr, INET_ADDRSTRLEN)
                              << " (" << ip << ") (re)registered at time "
                              << ctime_r(&(cs->_regTime), timestr));
                }

                /// client might be already currently registered

                /// if so, dont need to notify dr
                if (cs->_state != CS_ST_REGISTERED) {
                    notifyDR(ip);
                }

                // but always notify sp because we assume client is using new key materials
                notifyProxy(ip, g_hardcode_sharedkey ? g_hardcoded_sharedkey : sharedkey, sizeof sharedkey);

                cs->_state = CS_ST_REGISTERED;
            }
            else {
#if 0
                MYLOGINFO("   client "
                          << inet_ntop(AF_INET, &ip, addrstr, INET_ADDRSTRLEN)
                          << " (" << ip << ") not matched: " << string(ss.str()));
#endif
                // remove cs from map if client is not currently registered
                if (cs->_state != CS_ST_REGISTERED) {
                    clients.erase(ip);
#if 0
                    MYLOGDEBUG("   client removed from map -> new map size: " << clients.size());
#endif
                }
            }
        }
bail:
        continue;
    }
    return;
}

void signal_callback_handler(int signum)
{
    MYLOGINFO("Caught signal " << signum);
    // Cleanup and close up stuff here

    MYLOGINFO("waiting for handler threads to finish");
    g_terminate = true;

    for (u_int i = 0; i < g_handlerthreads.size(); ++i) {
        g_handlerthreads[i]->join();
    }

    MYLOGINFO("g_pktcount = " << g_pktcount);
    MYLOGINFO("exiting now");
    
    // Terminate program
    exit(signum);
}

int main(int argc, char **argv)
{

    char *dev = NULL;           /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */

    string filter_exp = "tcp and (tcp[tcpflags] == tcp-syn)"; /* filter expression [3] */
    struct bpf_program fp;          /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int opt;
    int long_index;
    u_short port = 0;
    const char *seckeypath = NULL;
    const char *proxyip = NULL;
    u_short proxyctlport = 0;
    const char *drIP = NULL;
    u_short drCtlPort = 0;
    boost::thread synpkthandler;
    BIO *curvesecretfilebio = NULL;
    int numThreads = 1;
    AppenderList al;

    printf("Revision: %s\n\n", rcsid);
    for (int i = 0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n\n");

    struct option long_options[] = {
        {"port", required_argument, 0, 1000},
        {"device", required_argument, 0, 1001},
        {"curveseckey", required_argument, 0, 1002},
        {"proxyip", required_argument, 0, 1003},
        {"proxyctlport", required_argument, 0, 1004},
        {"verbose", no_argument, 0, 1005},
        {"dont-compare-ciphertext", no_argument, 0, 1006},
        {"hardcode-sharedkey", required_argument, 0, 1007},
        {"drIP", required_argument, 0, 1008},
        {"drCtlPort", required_argument, 0, 1009},
        {"numThreads", required_argument, 0, 1010}, // should be power of 2
        {"validationInterval", required_argument, 0, 1011}, // in seconds
        {"garbageCollectionInterval", required_argument, 0, 1012}, // in seconds
        {"bytesPerISN", required_argument, 0, 1013}, // either 3 or 4
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
            port = strtod(optarg, NULL);
            break;

        case 1001:
            dev = optarg;
            break;

        case 1002:
            seckeypath = optarg;
            break;

        case 1003:
            proxyip = optarg;
            break;

        case 1004:
            proxyctlport = strtod(optarg, NULL);
            break;

        case 1005:
            g_verbose = true;
            break;

        case 1006:
            g_dont_cmp_ciphertext = true;
            break;

        case 1007:
            g_hardcode_sharedkey = true;
            memset(g_hardcoded_sharedkey, optarg[0],
                   sizeof g_hardcoded_sharedkey);
            break;

        case 1008:
            drIP = optarg;
            break;

        case 1009:
            drCtlPort = strtod(optarg, NULL);
            break;

        case 1010:
            numThreads = strtod(optarg, NULL);
            break;

        case 1011:
            g_validationInterval = strtod(optarg, NULL);
            assert (g_validationInterval >= 60 && g_validationInterval <= 3600);
            break;

        case 1012:
            g_garbagecollectioninterval = boost::posix_time::seconds(
                strtod(optarg, NULL));
            assert (g_garbagecollectioninterval.total_seconds() >= 60 &&
                    g_garbagecollectioninterval.total_seconds() <= 3600);
            break;

        case 1013:
            g_bytesPerISN = strtod(optarg, NULL);
            break;

        default:
            print_app_usage();
            exit(-1);
            break;
        }
    }

    bail_require_msg(g_bytesPerISN == 3 || g_bytesPerISN == 4,
                     "must specify --bytesPerISN with 3 or 4");
    g_numRequiredPkts = (uint8_t)ceil(((double)(CURVE25519_KEYSIZE + 4)) /
                                      g_bytesPerISN);

    bail_require_msg(drIP != NULL, "must specify --drIP");
    bail_require_msg(drCtlPort > 0, "must specify --drCtlPort");
    bail_require_msg(dev != NULL, "must specify --device");

    bail_require_msg(g_validationInterval != 0,
                     "must specify --validationInterval");
    bail_require_msg(g_garbagecollectioninterval.total_seconds() != 0,
                     "must specify --garbageCollectionInterval");

    bail_require_msg(
        (!g_dont_cmp_ciphertext) && (!g_hardcode_sharedkey),
        "'dont-compare-ciphertext' and 'hardcode-sharedkey' should be used "
        "only for testing");

    bail_require_msg(ISPOWEROF2(numThreads), "numThreads must be power of 2");

    if (seckeypath && g_hardcode_sharedkey) {
        fprintf(stderr, "dont use both --curveseckey and --hardcode-sharedkey\n");
        exit(-1);
    }
    if (!(seckeypath || g_hardcode_sharedkey) || !proxyip || !proxyctlport) {
        print_app_usage();
        exit(-1);
    }

    if (port > 0) {
        filter_exp += " and port ";
        filter_exp += lexical_cast<string>(port);
    }

    if (!g_hardcode_sharedkey) {
        curvesecretfilebio = BIO_new_file(seckeypath, "rb");
        bail_null(curvesecretfilebio);

        bail_require_msg(sizeof g_myseckey == BIO_read(curvesecretfilebio, g_myseckey, sizeof g_myseckey), "error reading secret curve key");
    }

    if (g_verbose) {
        if (!g_hardcode_sharedkey) {
            print_hex_ascii_line("secret key", g_myseckey, sizeof g_myseckey, 0);
        }
        else {
            print_hex_ascii_line("hardcoded sharedkey", g_hardcoded_sharedkey,
                                 sizeof g_hardcoded_sharedkey, 0);
        }
    }

    // Set up a simple configuration that logs on the console.
    log4cxx::BasicConfigurator::configure();
    g_logger->setLevel(log4cxx::Level::getInfo());

    al= g_logger->getAllAppenders();

    for (uint32_t i = 0; i < al.size(); ++i) {
        log4cxx::PatternLayoutPtr layout(new log4cxx::PatternLayout("%d [%t] (%F:%L) - %m%n"));
        al[i]->setLayout(layout);
    }

    /* create control socket to the proxy */
    g_proxyctlsocket = socket(PF_INET, SOCK_DGRAM, 0);
    bail_require(g_proxyctlsocket != -1);

    bzero(&g_proxyaddr,sizeof(g_proxyaddr));
    g_proxyaddr.sin_family = AF_INET;
    g_proxyaddr.sin_addr.s_addr=inet_addr(proxyip);
    g_proxyaddr.sin_port=htons(proxyctlport);

    /* create control socket to the DR */
    g_drCtlSocket = socket(PF_INET, SOCK_DGRAM, 0);
    bail_require(g_drCtlSocket != -1);

    bzero(&g_drAddr,sizeof(g_drAddr));
    g_drAddr.sin_family = AF_INET;
    g_drAddr.sin_addr.s_addr=inet_addr(drIP);
    g_drAddr.sin_port=htons(drCtlPort);
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Filter expression: %s\n\n", filter_exp.c_str());

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    memset(&fp, 0, sizeof fp);
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
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

    for (int i = 0; i < numThreads; ++i) {
        // create a clients table for each thread

        // partition the clients based on last 16 bits of ip address.
        uint32_t masked_ip = (i << 15);
        assert ((masked_ip & 1) == 0); // make sure 1's are not shifted in

        g_SYNqueues[masked_ip] = make_shared<ThreadSafeQueue<shared_ptr<SynPacket_t> > >();

        // XXX/leakin
        g_handlerthreads.push_back(new boost::thread(
                                       handleSynPackets, "rs-" + boost::lexical_cast<string>(masked_ip),
                                       g_SYNqueues[masked_ip]));
    }

    signal(SIGHUP, signal_callback_handler);
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);

    // set up the ip mask
    g_ipmask = (numThreads - 1) << 15;
    MYLOGINFO("g_ipmask = " << g_ipmask);
    MYLOGINFO("g_validationInterval = " << g_validationInterval);
    MYLOGINFO("g_garbagecollectioninterval = " << g_garbagecollectioninterval.total_seconds());
    MYLOGINFO("g_bytesPerISN = " << g_bytesPerISN);
    MYLOGINFO("g_numRequiredPkts = " << g_numRequiredPkts);

    /* now we can set our callback function */
    pcap_loop(handle, 0, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

bail:
    openssl_safe_free(BIO, curvesecretfilebio);
    return 0;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

    printf("Usage: %s [--curveseckey <curve25519 secret file>]\n"
           "          [--port <port>]\n"
           "          --proxyip ... --proxyctlport ... \n"
           "          --drIP ... --drCtlPort ... \n"
           "          --bytesPerISN ... \n"
           "          --validationInterval <seconds> --garbageCollectionInterval <seconds>\n"
           "          [--hardcode-sharedkey <one char>]\n"
           "          [--dont-compute-ciphertext]\n"
           "          [--device interface]\n", APP_NAME);
    printf("\n");

    return;
}
