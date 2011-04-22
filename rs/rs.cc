
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
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <assert.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <getopt.h>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <iostream>
#include "ThreadSafeQueue.hpp"
#include <boost/make_shared.hpp>
#include <map>
#include "common.hpp"

extern "C" {
#include "curve25519-20050915/curve25519.h"
}

static const char rcsid[] =
    "$Id$";

using std::string;
using std::cout;
using std::endl;
using std::map;

using boost::lexical_cast;
using boost::shared_ptr;
using boost::make_shared;

// we only need upto the tcp sequence number
#define SNAP_LEN (SIZE_ETHERNET + 60 + 2)

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

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

#define log cout << __FILE__ << ":" << __LINE__ << ": "

#define safe_free(ptr)                          \
  do {                                          \
    if ((ptr)) {                                \
      free(ptr);                                \
      ptr = NULL;                               \
    }                                           \
  }                                             \
  while (0)

#define openssl_safe_free(TYPE, ptr)            \
  do {                                          \
    if ((ptr)) {                                \
      TYPE##_free(ptr);                         \
      ptr = NULL;                               \
    }                                           \
  }                                             \
  while (0)

#define bail_error(err)                                                 \
  do {                                                                  \
    if ((err)) {                                                        \
      printf("error at %s:%d, %s()\n", __FILE__, __LINE__, __func__);   \
      goto bail;                                                        \
    }                                                                   \
  }                                                                     \
  while (0)

#define bail_null(ptr)                                                  \
  do {                                                                  \
    if (NULL == (ptr)) {                                                \
      printf("NULL error at %s:%d, %s()\n", __FILE__, __LINE__, __func__); \
      goto bail;                                                        \
    }                                                                   \
  }                                                                     \
  while (0)

#define bail_null_msg(ptr, msg)                                         \
  do {                                                                  \
    if (NULL == (ptr)) {                                                \
      printf("NULL error at %s:%d, %s(): %s\n", __FILE__, __LINE__, __func__, msg); \
      goto bail;                                                        \
    }                                                                   \
  }                                                                     \
  while (0)

#define bail_require(cond)                                              \
  do {                                                                  \
    if (!(cond)) {                                                      \
      printf("error condition at %s:%d, %s()\n", __FILE__, __LINE__, __func__); \
      goto bail;                                                        \
    }                                                                   \
  }                                                                     \
  while (0)

#define bail_require_msg(cond, msg)                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      printf("error condition at %s:%d, %s(): %s\n", __FILE__, __LINE__, __func__, msg); \
      goto bail;                                                        \
    }                                                                   \
  }                                                                     \
  while (0)

#define CURVE25519_KEYSIZE (32)


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
        : _state(CS_ST_PENDING), _pktcount(0) {}

    u_char _curvepubkey[CURVE25519_KEYSIZE];
    client_state_t _state;
    u_short _pktcount;
};

static ThreadSafeQueue<shared_ptr<SynPacket_t> > g_synpackets;
static u_char g_myseckey[CURVE25519_KEYSIZE] = {0};
static int g_proxyctlsocket = -1;
static struct sockaddr_in g_proxyaddr;

/*
 * get the various cryptographic stuff required for communicating with
 * the client.
 *
 * the aes key used for signalling messages is derived
 * kdf(sharedcurvekey + '1'), where '+' is concatenation.
 *
 * "rsciphertext" will be filled with the first 4 bytes of the cipher
 * text of the clear text "register" encrypted with the aes key.
 *
 * "proxysynciphertext" and "proxyackciphertext": as above, but the
 * clear texts are "syn" and "ack"; these are used for signalling
 * between client and proxy.
 *
 * "proxystreamcipher" is the stream cipher that will be used to
 * encrypt communication between client and
 * proxy. "proxystreamcipherkey" and "proxystreamcipheriv" will be
 * filled with the key and iv that should be used to initialize that
 * cipher.
*/
int
getclientcrypto(const u_char sharedcurvekey[CURVE25519_KEYSIZE],
              /* used for registering */
              u_char rsciphertext[4],
              /* used to signal to proxy */
              u_char proxysynciphertext[4],
                u_char proxyackciphertext[4],
                const EVP_CIPHER *proxystreamcipher,
                u_char proxystreamcipherkey[EVP_MAX_KEY_LENGTH],
                u_char proxystreamcipheriv[EVP_MAX_IV_LENGTH]
    )
{
  int err = 0;
  int retval = 0;
  static const char str[] = "register";
  static const char syn[] = "syn";
  static const char ack[] = "ack";
  BIO *ciphertextbio = NULL;
  BIO *benc = NULL;
  /// generate key and iv for cipher
  u_char cipherkey[EVP_MAX_KEY_LENGTH] = {0};
  u_char cipheriv[EVP_MAX_IV_LENGTH] = {0};
  const EVP_CIPHER *signallingcipher = EVP_aes_128_cbc();

  // data to derive cipher key/iv
  u_char kdf_data[CURVE25519_KEYSIZE + 1] = {0};

  bail_null(proxystreamcipher);

  // use the shared curve25519 key
  memcpy(kdf_data, sharedcurvekey, sizeof sharedcurvekey);
  // the last byte is "1" to derive the aes key
  kdf_data[(sizeof kdf_data) - 1] = '1';

  retval = EVP_BytesToKey(
      signallingcipher, EVP_sha1(), NULL, kdf_data, sizeof kdf_data, 1,
      cipherkey, cipheriv);
  bail_require(retval == signallingcipher->key_len);

  benc = BIO_new(BIO_f_cipher());
  bail_null(benc);

  BIO_set_cipher(benc, signallingcipher, cipherkey, cipheriv, 1);

  ciphertextbio = BIO_new(BIO_s_mem());
  bail_null(ciphertextbio);

  bail_require(BIO_push(benc, ciphertextbio) == benc);

  retval = BIO_write(benc, str, strlen(str));
  bail_require(retval == strlen(str));
  bail_require(1 == BIO_flush(benc)); // need to flush

  // read out the first 4 bytes of the regciphertext
  retval = BIO_read(ciphertextbio, rsciphertext, sizeof rsciphertext);
  bail_require(retval == sizeof rsciphertext);

  //////////////////////////
  // now get the cipher text for signalling the proxy and the expected
  // response

  retval = BIO_write(benc, syn, strlen(syn));
  bail_require(retval == strlen(syn));
  bail_require(1 == BIO_flush(benc));

  retval = BIO_read(ciphertextbio,
                    proxysynciphertext, sizeof proxysynciphertext);
  bail_require(retval == sizeof proxysynciphertext);

  retval = BIO_write(benc, ack, strlen(ack));
  bail_require(retval == strlen(ack));
  bail_require(1 == BIO_flush(benc));

  retval = BIO_read(ciphertextbio,
                    proxyackciphertext, sizeof proxyackciphertext);
  bail_require(retval == sizeof proxyackciphertext);

  /////// now get the key and iv for the stream cipher used for
  /////// communication between client and proxy

  memcpy(kdf_data, sharedcurvekey, sizeof sharedcurvekey);
  // the last byte is "2"
  kdf_data[(sizeof kdf_data) - 1] = '2';

  retval = EVP_BytesToKey(
      proxystreamcipher, EVP_sha1(), NULL, kdf_data, sizeof kdf_data, 1,
      proxystreamcipherkey, proxystreamcipheriv);
  bail_require(retval == proxystreamcipher->key_len);

bail:
  openssl_safe_free(BIO, benc);
  openssl_safe_free(BIO, ciphertextbio);
  return err;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

//	static int count = 0;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
    shared_ptr<SynPacket_t> synpkt;
	int size_ip;
	int size_tcp;
	
	// printf("\nPacket number %d:\n", count);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	// /* print source and destination IP addresses */
	// printf("       From: %s\n", inet_ntoa(ip->ip_src));
	// printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    bail_require_msg(ip->ip_p == IPPROTO_TCP, "getting non-TCP packets");

	// /* determine protocol */	
	// switch(ip->ip_p) {
	// 	case IPPROTO_TCP:
	// 		printf("   Protocol: TCP\n");
	// 		break;
	// 	case IPPROTO_UDP:
	// 		printf("   Protocol: UDP\n");
	// 		return;
	// 	case IPPROTO_ICMP:
	// 		printf("   Protocol: ICMP\n");
	// 		return;
	// 	case IPPROTO_IP:
	// 		printf("   Protocol: IP\n");
	// 		return;
	// 	default:
	// 		printf("   Error: getting non-TCP packets\n");
	// 		return;
	// }
	
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

    bail_require_msg(tcp->th_flags & TH_SYN, "getting non-SYN packets");

    synpkt = make_shared<SynPacket_t>(ip->ip_src.s_addr, (u_char*)&(tcp->th_seq));
    g_synpackets.put(synpkt);

#if 0
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	printf("   seq num:  %d\n", ntohs(tcp->th_seq));

    static u_char clientpubkey[CURVE25519_KEYSIZE] = {0};
    static u_char sharedkey[CURVE25519_KEYSIZE] = {0};
    static const int numrequiredpackets = (CURVE25519_KEYSIZE + 4) / 4;
    if (count < (numrequiredpackets - 1)) {
      memcpy(clientpubkey + (count * 4), &(tcp->th_seq), 4);
      count++;
    }
    else {
      /* we should have the client pubkey and the uniquifier now */
      const u_char *myseckey = args;
      curve25519(sharedkey, myseckey, clientpubkey);
      u_char rsciphertext[4] = {0};
      u_char proxysynciphertext[4] = {0};
      u_char proxyackciphertext[4] = {0};
      bail_error(getclientcrypto(sharedkey, rsciphertext,
                                 proxysynciphertext, proxyackciphertext));
      if (0 == memcmp(rsciphertext, &(tcp->th_seq), 4)) {
        printf("\n   Uniquifier matched!\n");
      }
      else {
        printf("\n   Uniquifier DO NOT match!\n");
      }
      count = 0;
    }

#endif

bail:
    return;
}

static void
notifyProxy(const u_long& src_ip,
            const u_char *proxysynciphertext,
            const u_char *proxyackciphertext,
            const u_char *proxystreamcipherkey,
            const int& proxystreamcipherkeylen,
            const u_char *proxystreamcipheriv,
            const int& proxystreamcipherivlen)
{
    int msglen;
    u_long ip = htonl(src_ip);

    bail_require(g_proxyctlsocket > -1);

    /* 4 each for src ip, syn and ack ciphertext */
    static u_char msg[12 + EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];

    memcpy(msg + 0, &ip, 4);
    memcpy(msg + 4, proxysynciphertext, 4);
    memcpy(msg + 8, proxyackciphertext, 4);
    memcpy(msg + 12,
           proxystreamcipherkey, proxystreamcipherkeylen);
    memcpy(msg + 12 + proxystreamcipherkeylen,
           proxystreamcipheriv, proxystreamcipherivlen);

    /* best effort, no guarantee */
    msglen = 12 + proxystreamcipherkeylen + proxystreamcipherivlen;
    bail_require(
        msglen == sendto(g_proxyctlsocket, msg, msglen, MSG_DONTWAIT,
                         (struct sockaddr*)&g_proxyaddr, sizeof g_proxyaddr));

bail:
    return;
}

static void
handleSynPackets()
{
    static map<u_long, shared_ptr<ClientState_t> > clients;

    while (true) {
        shared_ptr<SynPacket_t> synpkt = g_synpackets.get();
        if (synpkt == NULL) {
            continue;
        }
        // put it in the appropriate table entry
        const u_long ip = synpkt->_ip_src;
        shared_ptr<ClientState_t> cs;
        if (Common::inMap(clients, ip)) {
            cs = clients[ip];
        }
        else {
            cs = make_shared<ClientState_t>();
            // put it into the map
            clients[ip] = cs;
            struct in_addr tmp;
            tmp.s_addr = ip;
            log << " new pending client ip: " << inet_ntoa(tmp) << endl;
        }

        ///// at this point, cs is a valid entry in the map /////

        // increment first
        cs->_pktcount += 1;
        if (cs->_pktcount < 9) {
            // need more pkts
            memcpy(cs->_curvepubkey + ((cs->_pktcount - 1) * 4), synpkt->_tcp_seq, 4);
        }
        else {
            u_char sharedkey[CURVE25519_KEYSIZE] = {0};
            u_char rsciphertext[4] = {0};
            u_char proxysynciphertext[4] = {0};
            u_char proxyackciphertext[4] = {0};
            u_char proxystreamcipherkey[EVP_MAX_KEY_LENGTH] = {0};
            u_char proxystreamcipheriv[EVP_MAX_IV_LENGTH] = {0};
            static const EVP_CIPHER* proxystreamcipher = EVP_rc4();

            // have received the final pkt --> check uniquifier
            curve25519(sharedkey, g_myseckey, cs->_curvepubkey);
            bail_error(getclientcrypto(sharedkey,
                                       rsciphertext,
                                       proxysynciphertext, proxyackciphertext,
                                       proxystreamcipher,
                                       proxystreamcipherkey,
                                       proxystreamcipheriv));
            if (0 == memcmp(rsciphertext, synpkt->_tcp_seq, 4)) {
                log << "\n   Uniquifier matched! client is now registered" << endl;
                cs->_state = CS_ST_REGISTERED;
                // reset pkt count
                cs->_pktcount = 0;

                notifyProxy(ip, proxysynciphertext, proxyackciphertext,
                            proxystreamcipherkey, proxystreamcipher->key_len,
                            proxystreamcipheriv, proxystreamcipher->iv_len);
            }
            else {
                log << "\n   Uniquifier DO NOT match" << endl;
                // remove cs from map
                clients.erase(ip);
            }
        }
        log << "map size: " << clients.size() << endl;
bail:
        continue;
    }
    return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	string filter_exp = "tcp port ";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */
    int opt;
    int long_index;
    u_short port = 0;
    const char *seckeypath = NULL;
    const char *proxyip = NULL;
    u_short proxyctlport = 0;
    boost::thread synpkthandler;

    struct option long_options[] = {
        {"port", required_argument, 0, 1000},
        {"device", required_argument, 0, 1001},
        {"curveseckey", required_argument, 0, 1002},
        {"proxyip", required_argument, 0, 1003},
        {"proxyctlport", required_argument, 0, 1004},
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

        default:
            print_app_usage();
            exit(-1);
            break;
        }
    }

    if (!port || !seckeypath || !proxyip || !proxyctlport) {
        print_app_usage();
        exit(-1);
    }

    filter_exp += lexical_cast<string>(port);

    BIO *curvesecretfilebio = BIO_new_file(seckeypath, "rb");
    bail_null(curvesecretfilebio);

    bail_require_msg(sizeof g_myseckey == BIO_read(curvesecretfilebio, g_myseckey, sizeof g_myseckey), "error reading secret curve key");

    /* create control socket to the proxy */
    g_proxyctlsocket = socket(PF_INET, SOCK_DGRAM, 0);
    bail_require(g_proxyctlsocket != -1);

    bzero(&g_proxyaddr,sizeof(g_proxyaddr));
    g_proxyaddr.sin_family = AF_INET;
    g_proxyaddr.sin_addr.s_addr=inet_addr(proxyip);
    g_proxyaddr.sin_port=htons(proxyctlport);

	if (dev == NULL) {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp.c_str());

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

    synpkthandler = boost::thread(handleSynPackets);

	/* now we can set our callback function */
//	pcap_loop(handle, num_packets, got_packet, myseckey);
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
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s --curveseckey <curve25519 secret file> --port <port>\n"
           "          --proxyip ... --proxyctlport ... \n"
           "          [--device interface]\n", APP_NAME);
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
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
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
