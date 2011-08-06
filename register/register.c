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
#include <ctype.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "curve25519-20050915/curve25519.h"
#include <math.h>

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
    tcph_cwr:1       /*congestion window reduced*/
  //    tcph_res2:2;
      ;

  unsigned short int tcph_win;
  unsigned short int tcph_chksum;
  unsigned short int tcph_urgptr;
};

#define CURVE25519_KEYSIZE (32)

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

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const char *header /* optional */,
                     const unsigned char *payload, int len, int offset,
                     const int hexonly)
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

void computepublickey(unsigned char pub[CURVE25519_KEYSIZE], const unsigned char secret[CURVE25519_KEYSIZE])
{
  static const unsigned char basepoint[CURVE25519_KEYSIZE] = {9};
  curve25519(pub,secret,basepoint);
}

int
getciphertext(const u_char *sharedcurvekey,
              /* used for registering */
              u_char *rsciphertext /* [4] */,
              /* used to signal to proxy */
              u_char *proxysynciphertext /*[4]*/,
              u_char *proxyackciphertext /*[4]*/
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

  print_hex_ascii_line("cipherkey", cipherkey, sizeof cipherkey, 0, 1);
  print_hex_ascii_line("cipheriv ", cipheriv, sizeof cipheriv, 0, 1);

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


bail:
  openssl_safe_free(BIO, benc);
  openssl_safe_free(BIO, ciphertextbio);
  return err;
}

int main(int argc, char *argv[])
{
  int sd;
// No data, just datagram
  char buffer[PCKT_LEN];

  struct tcpheader *tcp = (struct tcpheader *) (buffer);
  struct sockaddr_in din;
  int zero = 0;
  const int *val = &zero;

  memset(buffer, 0, PCKT_LEN);

  if(argc != 5)
  {
    printf("- Invalid parameters!!!\n");
    printf("- Usage: %s <target IP> <target port> <RS curve25519 pubkey file> <3 or 4 (bytes per ISN)?>\n", argv[0]);
    printf("  - RS is 'registration server'\n");
    printf("  - the target is some host (might not even exist) such that our\n");
    printf("    packets are routed through to the registration server\n");
    exit(-1);
  }

  const unsigned int bytesPerISN = strtod(argv[4], NULL);
  assert (bytesPerISN == 3 || bytesPerISN == 4);

  BIO *rspubkeybio = BIO_new_file(argv[3], "rb");
  bail_null_msg(rspubkeybio, "can't open RS pubkey file");

  u_char rspubkey[CURVE25519_KEYSIZE] = {0};
  bail_require_msg(BIO_read(rspubkeybio, rspubkey, sizeof rspubkey) == sizeof rspubkey,
                   "error reading RS pubkey");

  u_char myseckey[CURVE25519_KEYSIZE] = {0};
  gensecretkey(myseckey);
  u_char mypubkey[CURVE25519_KEYSIZE] = {0};
  computepublickey(mypubkey, myseckey);

  u_char sharedkey[CURVE25519_KEYSIZE] = {0};
  curve25519(sharedkey, myseckey, rspubkey);

  u_char rsciphertext[4] = {0};
  u_char proxysynciphertext[4] = {0};
  u_char proxyackciphertext[4] = {0};
  bail_error(getciphertext(sharedkey, rsciphertext,
                           proxysynciphertext, proxyackciphertext));

//  print_hex_ascii_line("esignal", rsciphertext, sizeof rsciphertext, 0, 1);

  u_char signal[sizeof mypubkey + sizeof rsciphertext];
  memcpy(signal, mypubkey, sizeof mypubkey);
  memcpy(signal + sizeof mypubkey, rsciphertext, sizeof rsciphertext);

  print_hex_ascii_line("pubkey+ciphertext", signal, sizeof signal, 0, 1);
  print_hex_ascii_line("sharedkey", sharedkey, sizeof sharedkey, 0, 1);

  /// handle the socket stuff

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
  din.sin_family = AF_INET;

// destination IP
  din.sin_addr.s_addr = inet_addr(argv[1]);


// The TCP structure.

// The destination port, we accept through command line

  tcp->tcph_destport = htons(atoi(argv[2]));
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

  printf("Using:::::Target IP: %s port: %u.\n", argv[1], atoi(argv[2]));

// sendto() loop, send every 2 second for 50 counts

  const int numrequiredpackets = ceil(((double)(sizeof signal)) / bytesPerISN);
  printf("numrequiredpackets = %d\n", numrequiredpackets);
  unsigned int count;
  for(count = 0; count < numrequiredpackets; count++)
  {
    bzero(&tcp->tcph_seqnum, sizeof tcp->tcph_seqnum);
    memcpy(&tcp->tcph_seqnum, signal + (bytesPerISN * count), bytesPerISN);

    assert(1 == RAND_bytes((unsigned char*)&(tcp->tcph_srcport),
                           sizeof(tcp->tcph_srcport)));

    size_t numsent = sendto(sd, buffer, 4 * tcp->tcph_dataoffset, 0, (struct sockaddr *)&din, sizeof(din));
    if(numsent != sizeof (struct tcpheader))
    {
      perror("sendto() error");
      exit(-1);
    }
    else
    {
      printf("Count #%u - sendto() is OK: ", count);
      printf("tcp seqnum = 0x%x\n", tcp->tcph_seqnum);
    }
    sleep(0.5);
  }

bail:
  close(sd);
  openssl_safe_free(BIO, rspubkeybio);
  return 0;
}
