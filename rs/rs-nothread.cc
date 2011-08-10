
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
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <iostream>
#include <boost/make_shared.hpp>
#include <map>
#include "common.hpp"
#include <math.h>
#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>
#include <vector>

extern "C" {
#ifdef USE64
#include "../curve25519-donna-c64.c"
int (*curve25519)(unsigned char *,const unsigned char *,const unsigned char *) = curve25519_donna;
#else
#include "curve25519-20050915/curve25519.h"
#endif
}

static const char rcsid[] =
    "$Id$";

using std::string;
using std::cout;
using std::endl;
using std::map;
using std::vector;

using boost::lexical_cast;
using boost::shared_ptr;
using boost::make_shared;

// we only need upto the tcp sequence number
#define SNAP_LEN (SIZE_ETHERNET + 60 + 2)

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

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

#define CURVE25519_KEYSIZE (32)

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

    u_char _signal[CURVE25519_KEYSIZE + 4];
    client_state_t _state;
    u_short _pktcount;
    time_t _lastSeen;
    time_t _regTime;
};

static u_char g_myseckeybase6[CURVE25519_KEYSIZE] = {0};
static u_char g_myseckeybase3[CURVE25519_KEYSIZE] = {0};
static int g_proxyctlsocket = -1;
static struct sockaddr_in g_proxyaddr;
static int g_drCtlSocket = -1;
static struct sockaddr_in g_drAddr;
bool g_verbose = false;
static bool g_terminate = false;
static uint32_t g_validationInterval = 0;
static uint32_t g_bytesPerISN = 0;
static uint32_t g_numRequiredPkts = 0;
static unsigned long long g_numClientsGarbageCollected = 0;

static pcap_t *g_handle = NULL; /* packet capture handle */
static unsigned long long g_pktCount = 0; // num of pkts handled here
static unsigned long long g_regCount = 0; // num of successful registrations
static unsigned long long g_regCount_base6 = 0; // num of successful
                                                // reg using base-4
static unsigned long long g_regCount_base3 = 0; // num of successful
                                                // reg using base-3
static unsigned long long g_cryptoCount = 0; // num of times we need to do crypto ops

static const int g_machdrlen = SIZE_ETHERNET;

static map<uint32_t, shared_ptr<ClientState_t> > g_clients;

static const EVP_CIPHER *g_signallingcipher = EVP_aes_128_cbc();
static const EVP_MD *g_signallinghash = EVP_sha1();
static const u_char g_register_str[] = "register";
#define REGISTER_STRLEN ((sizeof g_register_str) - 1)

static void
notifyProxy(const uint32_t& src_ip,
            const u_char *kdf_data,
            const int& kdf_data_len);

static void
notifyDR(const uint32_t& src_ip);

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
print_app_usage(void);

void
got_packet(const uint32_t& clientipaddr, const uint32_t& ISN)
{
    shared_ptr<ClientState_t> cs;
    time_t now;
    char addrstr[INET_ADDRSTRLEN];

    g_pktCount ++;

    if (Common::inMap(g_clients, clientipaddr)) {
        cs = g_clients[clientipaddr];
        // XXX/hmm when replaying the SYNonly100K trace at top speed
        // against rs-nothread, it would crash at cs->_lastSeen
        // ... below because cs is null, which is tracked here, where
        // the clientipaddr never was added to the map, yet inMap
        // returns true

        // work around this here.
        if (!cs) {
            log << "WARN: inMap says client is in g_clients, but the client "
                << "state is NULL" << endl;
            cs = make_shared<ClientState_t>();
            assert (cs);
            // put it into the map
            g_clients[clientipaddr] = cs;
        }
    }
    else {
        cs = make_shared<ClientState_t>();
        assert (cs);
        // put it into the map
        g_clients[clientipaddr] = cs;
    }

    ///// at this point, cs is a valid entry in the map /////

    // update last seen
    now = time(NULL);
    cs->_lastSeen = now;

    // increment first
    cs->_pktcount += 1;

    memcpy(cs->_signal + ((cs->_pktcount - 1) * g_bytesPerISN),
           &(ISN), g_bytesPerISN);

    if (cs->_pktcount == g_numRequiredPkts) {
        // we have enough packets --> detect signal
        u_char sharedkey[CURVE25519_KEYSIZE];
        curve25519(sharedkey, g_myseckeybase6, cs->_signal);

        if (g_verbose) {
            print_hex_ascii_line("sharedkey base-6",
                                 sharedkey, sizeof sharedkey, 0);
        }
        u_char kdf_data[(sizeof sharedkey) + 1];
        memcpy(kdf_data, sharedkey, sizeof sharedkey);
        kdf_data[(sizeof kdf_data) - 1] = '1'; // '1' for signalling

        u_char cipherkey[EVP_MAX_KEY_LENGTH];
        u_char cipheriv[EVP_MAX_IV_LENGTH];

        int retval = EVP_BytesToKey(
            g_signallingcipher, g_signallinghash,
            NULL, kdf_data, sizeof kdf_data, 1,
            cipherkey, cipheriv);
        bail_require(retval == g_signallingcipher->key_len);

        u_char rsciphertext[4];
        bail_error(encrypt(g_signallingcipher, cipherkey, cipheriv,
                           g_register_str, REGISTER_STRLEN,
                           rsciphertext, sizeof rsciphertext));

        g_cryptoCount ++;

        // reset pkt count
        cs->_pktcount = 0;

        if (!memcmp(rsciphertext, cs->_signal + CURVE25519_KEYSIZE, 4)) {
            g_regCount++;
            g_regCount_base6++;

            cs->_regTime = now;

            if (g_verbose) {
                char timestr[30];
                log << "   client "
                    << inet_ntop(AF_INET, &clientipaddr, addrstr, INET_ADDRSTRLEN)
                    << " (" << clientipaddr << ") (re)registered at time "
                    << ctime_r(&(cs->_regTime), timestr);
            }

            /// client might be already currently registered

            /// if so, dont need to notify dr
            if (cs->_state != CS_ST_REGISTERED) {
                notifyDR(clientipaddr);
            }

            // but always notify sp because we assume client is using
            // new key materials
            notifyProxy(clientipaddr, sharedkey, sizeof sharedkey);

            cs->_state = CS_ST_REGISTERED;
        }
        else {
            // no match using base-6, now try base-3
            curve25519(sharedkey, g_myseckeybase3, cs->_signal);

            if (g_verbose) {
                print_hex_ascii_line("sharedkey base-3",
                                     sharedkey, sizeof sharedkey, 0);
            }
            memcpy(kdf_data, sharedkey, sizeof sharedkey);
            kdf_data[(sizeof kdf_data) - 1] = '1'; // '1' for signalling

            int retval = EVP_BytesToKey(
                g_signallingcipher, g_signallinghash,
                NULL, kdf_data, sizeof kdf_data, 1,
                cipherkey, cipheriv);
            bail_require(retval == g_signallingcipher->key_len);

            bail_error(encrypt(g_signallingcipher, cipherkey, cipheriv,
                               g_register_str, REGISTER_STRLEN,
                               rsciphertext, sizeof rsciphertext));

            if (!memcmp(rsciphertext, cs->_signal + CURVE25519_KEYSIZE, 4)) {
                g_regCount++;
                g_regCount_base3++;

                cs->_regTime = now;

                if (g_verbose) {
                    char timestr[30];
                    log << "   client "
                        << inet_ntop(AF_INET, &clientipaddr, addrstr, INET_ADDRSTRLEN)
                        << " (" << clientipaddr << ") (re)registered at time "
                        << ctime_r(&(cs->_regTime), timestr);
                }

                /// client might be already currently registered

                /// if so, dont need to notify dr
                if (cs->_state != CS_ST_REGISTERED) {
                    notifyDR(clientipaddr);
                }

                // but always notify sp because we assume client is
                // using new key materials
                notifyProxy(clientipaddr, sharedkey, sizeof sharedkey);

                cs->_state = CS_ST_REGISTERED;
            }
            else {
//            log << "\n   ciphertext does not match" << endl;
                // remove cs from map if client is not currently registered
                if (cs->_state != CS_ST_REGISTERED) {
                    g_clients.erase(clientipaddr);
                }
            }
        }
    }

bail:
    return;
}

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

static void
collectGarbage(const time_t& now)
{
    // loop thru the g_clients
    printf("%s: starting garbage collection\n", ctime(&now));
    map<uint32_t, shared_ptr<ClientState_t> >::iterator cit = g_clients.begin();
    while (cit != g_clients.end()) {
        const shared_ptr<ClientState_t>& cs = cit->second;
        if (cs->_state == CS_ST_PENDING && (now > (cs->_lastSeen + (int)g_validationInterval))) {
            g_clients.erase(cit++);
            g_numClientsGarbageCollected ++;
        }
        else {
            ++cit;
        }
    }
    printf("%s: done garbage collection\n", ctime(&now));
    return;
}

void signal_callback_handler(int signum)
{
    printf("Caught signal %d\n", signum);
    // Cleanup and close up stuff here

    g_terminate = true;

    pcap_breakloop(g_handle);
}

int main(int argc, char **argv)
{
    int err = 1;
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	string filter_exp = "tcp and (tcp[tcpflags] == tcp-syn)";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
    int opt;
    int long_index;
    u_short port = 0;
    const char *seckeybase6path = NULL;
    const char *seckeybase3path = NULL;
    const char *proxyip = NULL;
    u_short proxyctlport = 0;
    const char *drIP = NULL;
    u_short drCtlPort = 0;
    BIO *curvesecretfilebio = NULL;
    uint32_t garbagecollectioninterval = 0;
    string srcAddrMaskValStr;
    uint32_t srcAddrMask = 0;
    uint32_t srcAddrVal = 0;
    boost::hash<uint32_t> srcAddrHasher;

	printf("Revision: %s\n\n", rcsid);
    for (int i = 0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n\n");

    struct option long_options[] = {
        {"port", required_argument, 0, 1000},
        {"device", required_argument, 0, 1001},
        {"proxyip", required_argument, 0, 1003},
        {"proxyctlport", required_argument, 0, 1004},
        {"verbose", no_argument, 0, 1005},
        {"drIP", required_argument, 0, 1008},
        {"drCtlPort", required_argument, 0, 1009},
        {"validationInterval", required_argument, 0, 1010}, // in seconds
        {"garbageCollectionInterval", required_argument, 0, 1011}, // in seconds
        {"bytesPerISN", required_argument, 0, 1012}, // either 3 or 4

        // arg should be "<mask>/<val>", where both are decimal
        // integers
        {"partitionByHash", required_argument, 0, 1013},

        {"seckey-base6", required_argument, 0, 1014},
        {"seckey-base3", required_argument, 0, 1015},

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

        case 1003:
            proxyip = optarg;
            break;

        case 1004:
            proxyctlport = strtod(optarg, NULL);
            break;

        case 1005:
            g_verbose = true;
            break;

        case 1008:
            drIP = optarg;
            break;

        case 1009:
            drCtlPort = strtod(optarg, NULL);
            break;

        case 1010:
            g_validationInterval = strtod(optarg, NULL);
            assert (g_validationInterval >= 60 && g_validationInterval <= 3600);
            break;

        case 1011:
            garbagecollectioninterval = strtod(optarg, NULL);
            assert (garbagecollectioninterval >= 60 &&
                    garbagecollectioninterval <= 3600);
            break;

        case 1012:
            g_bytesPerISN = strtod(optarg, NULL);
            break;

        case 1013:
            srcAddrMaskValStr = optarg;
            boost::trim(srcAddrMaskValStr);
            assert(srcAddrMaskValStr.length() > 0);
            break;

        case 1014:
            seckeybase6path = optarg;
            break;

        case 1015:
            seckeybase3path = optarg;
            break;

        default:
            print_app_usage();
            exit(-1);
            break;
        }
    }

    if (srcAddrMaskValStr.length() > 0) {
        vector<string> tokens;
        boost::split(tokens, srcAddrMaskValStr, boost::is_any_of("/"));
        bail_require_msg(tokens.size() == 2, "must be \"<mask>/<val>\"");
        srcAddrMask = boost::lexical_cast<uint32_t>(tokens[0]);
        srcAddrVal = boost::lexical_cast<uint32_t>(tokens[1]);
        printf("partition mask: 0x%X, value: 0x%X\n", srcAddrMask, srcAddrVal);
    }

    bail_require_msg(g_bytesPerISN == 3 || g_bytesPerISN == 4,
                     "must specify --bytesPerISN with 3 or 4");
    g_numRequiredPkts = (uint8_t)ceil(((double)(CURVE25519_KEYSIZE + 4)) /
                                      g_bytesPerISN);

    bail_require_msg(g_validationInterval != 0,
                     "must specify --validationInterval");
    bail_require_msg(garbagecollectioninterval != 0,
                     "must specify --garbageCollectionInterval");

    bail_require_msg(dev, "must specify --device");

    bail_require_msg(seckeybase6path != NULL, "must specify --seckey-base6");
    bail_require_msg(seckeybase3path != NULL, "must specify --seckey-base3");

    if (!proxyip || !proxyctlport) {
        print_app_usage();
        exit(-1);
    }

    if (port > 0) {
        filter_exp += " and port ";
        filter_exp += lexical_cast<string>(port);
    }

    // read in the secret keys
    curvesecretfilebio = BIO_new_file(seckeybase6path, "rb");
    bail_null(curvesecretfilebio);

    bail_require_msg(
        sizeof g_myseckeybase6 == BIO_read(
            curvesecretfilebio, g_myseckeybase6, sizeof g_myseckeybase6),
        "error reading secret base-6 key");

    if (g_verbose) {
        print_hex_ascii_line("secret key base-6",
                             g_myseckeybase6, sizeof g_myseckeybase6, 0);
    }
    openssl_safe_free(BIO, curvesecretfilebio);

    curvesecretfilebio = BIO_new_file(seckeybase3path, "rb");
    bail_null(curvesecretfilebio);

    bail_require_msg(
        sizeof g_myseckeybase3 == BIO_read(
            curvesecretfilebio, g_myseckeybase3, sizeof g_myseckeybase3),
        "error reading secret base-3 key");

    if (g_verbose) {
        print_hex_ascii_line("secret key base-3",
                             g_myseckeybase3, sizeof g_myseckeybase3, 0);
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

	/* print capture info */
	printf("Filter expression: %s\n", filter_exp.c_str());
    printf("g_validationInterval = %d\n", g_validationInterval);
    printf("garbagecollectioninterval = %d\n", garbagecollectioninterval);
    printf("g_bytesPerISN = %u\n", g_bytesPerISN);
    printf("g_numRequiredPkts = %u\n", g_numRequiredPkts);

	/* open capture device */
    /* 15 second timeout */
	g_handle = pcap_open_live(dev, SNAP_LEN, 1, 15000, errbuf);
	if (g_handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(g_handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

    memset(&fp, 0, sizeof fp);
	/* compile the filter expression */
	if (pcap_compile(g_handle, &fp, filter_exp.c_str(), 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp.c_str(), pcap_geterr(g_handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(g_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp.c_str(), pcap_geterr(g_handle));
		exit(EXIT_FAILURE);
	}

    signal(SIGHUP, signal_callback_handler);
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);

    const u_char *packet;		/* The actual packet */
    struct pcap_pkthdr header;
    time_t lastGarbageCollection;
    lastGarbageCollection = time(NULL);
    while (!g_terminate) {
        {
            const time_t now = time(NULL);
            if (now > (lastGarbageCollection + (int)garbagecollectioninterval)) {
                lastGarbageCollection = now;
                collectGarbage(now);
            }
        }
        packet = pcap_next(g_handle, &header);
        if (packet) {
            // assumes there is enough captured data, and the pcap
            // filter does its job correctly: that only ipv4 tcp syn
            // packets are captured. so we dont check those things
            // here.
            const struct sniff_ip *ip = (struct sniff_ip*)(
                packet + g_machdrlen);
            const int iphdrlen = IP_HL(ip)*4;
            const struct sniff_tcp *tcp = (struct sniff_tcp*)(
                packet + g_machdrlen + iphdrlen);

            // now filter out packets that are not in our partition
            if (srcAddrMask != 0 &&
                ((srcAddrHasher(ip->ip_src.s_addr) & srcAddrMask) != srcAddrVal))
            {
                continue;
            }
            got_packet(ip->ip_src.s_addr, tcp->th_seq);
        }
    }

    printf("pktCount = %llu\n", g_pktCount);
    printf("cryptoCount = %llu\n", g_cryptoCount);
    printf("g_numClientsGarbageCollected = %llu\n", g_numClientsGarbageCollected);
    printf("g_regCount = %llu\n", g_regCount);
    printf("g_regCount_base6 = %llu\n", g_regCount_base6);
    printf("g_regCount_base3 = %llu\n", g_regCount_base3);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(g_handle);

	printf("\nCapture complete.\n");

    err = 0;

bail:
    openssl_safe_free(BIO, curvesecretfilebio);

    return err;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s --seckey-base6 <path> --seckey-base3 <path>\n"
           "          [--port <capture only this port>]\n"
           "          --proxyip ... --proxyctlport ... \n"
           "          --drIP ... --drCtlPort ... \n"
           "          --bytesPerISN <3 or 4> \n"
           "          --validationInterval <seconds> --garbageCollectionInterval <seconds>\n"
           "          --device interface\n", APP_NAME);
	printf("\n");
	printf("if partitionByHash is specified, the client's src ip address\n"
           "will be hashed with boost::hash<uint32_t>, then masked with\n"
           "the specified <mask>, and the packet is used only if the result\n"
           "equals the <value after masked>.\n"
        );

    return;
}
