/* modified code from http://www.tenouk.com/Module43a.html */

//---cat rawtcp.c---

// Run as root or SUID 0, just datagram no data/payload
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <assert.h>

static const char Id[] =
    "$Id$";

// Packet length
#define PCKT_LEN 8192

/* Structure of a TCP header */

struct tcpheader {
  unsigned short int tcph_srcport;
  unsigned short int tcph_destport;
  unsigned int       tcph_seqnum;
  unsigned int       tcph_acknum;
  unsigned char      tcph_reserved:4, tcph_dataoffset:4;

  // unsigned char tcph_flags;
  unsigned int
  //    tcp_res1:4,       /*little-endian*/
  //    tcph_hlen:4,      /*length of tcp header in 32-bit words*/
    tcph_fin:1,       /*Finish flag "fin"*/
    tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
    tcph_rst:1,       /*Reset flag */
    tcph_psh:1,       /*Push, sends data to the application*/
    tcph_ack:1,       /*acknowledge*/
    tcph_urg:1,       /*urgent pointer*/
    tcph_ece:1,       /*ecn-echo*/
    tcph_cwr:1,       /*congestion window reduced*/
  //    tcph_res2:2;
      ;

  unsigned short int tcph_win;
  unsigned short int tcph_chksum;
  unsigned short int tcph_urgptr;
};

int main(int argc, char *argv[])
{
  int sd;
// No data, just datagram
  char buffer[PCKT_LEN];

  struct tcpheader *tcp = (struct tcpheader *) (buffer);
  struct sockaddr_in sin, din;
  int zero = 0;
  const int *val = &zero;

  memset(buffer, 0, PCKT_LEN);

  if(argc != 5)
  {
    printf("- Invalid parameters!!!\n");
    printf("- Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
    exit(-1);
  }

  sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  if(sd < 0)
  {
    perror("socket() error");
    exit(-1);
  }
  else
  {
    printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
  }

// Address family
  sin.sin_family = AF_INET;
  din.sin_family = AF_INET;

// Source port, can be any, modify as needed
  sin.sin_port = htons(atoi(argv[2]));
  din.sin_port = htons(atoi(argv[4]));

// Source IP, can be any, modify as needed
  sin.sin_addr.s_addr = inet_addr(argv[1]);
  din.sin_addr.s_addr = inet_addr(argv[3]);


// The TCP structure. The source port, spoofed, we accept through the command line

//  tcp->tcph_srcport = htons(atoi(argv[2]));

// The destination port, we accept through command line

  tcp->tcph_destport = htons(atoi(argv[4]));
  tcp->tcph_acknum = 0;
  tcp->tcph_dataoffset = 5; /* no tcp options -> 20 bytes/5 words */
  tcp->tcph_syn = 1;
  tcp->tcph_ack = 0;
  tcp->tcph_win = htons(32767);
  tcp->tcph_chksum = 0; // Done by kernel
  tcp->tcph_urgptr = 0;

// Inform the kernel to fill up the ip header' structure

  if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) != 0)
  {
    perror("setsockopt() error");
    exit(-1);
  }
  else
  {
    printf("setsockopt() is OK\n");
  }

  printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

// sendto() loop, send every 2 second for 50 counts

  unsigned int count;
  for(count = 0; count < 5; count++)
  {
      assert(1 == RAND_bytes((unsigned char*)&(tcp->tcph_seqnum),
                             sizeof(tcp->tcph_seqnum)));
      tcp->tcph_seqnum = htonl(tcp->tcph_seqnum);

      assert(1 == RAND_bytes((unsigned char*)&(tcp->tcph_srcport),
                             sizeof(tcp->tcph_srcport)));

    size_t numsent = sendto(sd, buffer, 4 * tcp->tcph_dataoffset, 0, (struct sockaddr *)&sin, sizeof(sin));
    if(numsent != sizeof (struct tcpheader))
    {
      perror("sendto() error");
      exit(-1);
    }
    else
    {
      printf("Count #%u - sendto() is OK\n", count);
    }
    sleep(0.1);
  }

  close(sd);

  return 0;
}
