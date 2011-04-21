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
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "curve25519-20050915/curve25519.h"

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
getciphertext(const u_char sharedcurvekey[CURVE25519_KEYSIZE],
              u_char ciphertext[4])
{
  int err = 0;
  /// generate key and iv for cipher
  u_char cipherkey[EVP_MAX_KEY_LENGTH] = {0};
  u_char cipheriv[EVP_MAX_IV_LENGTH] = {0};

  // data to derive cipher key/iv
  u_char kdf_data[CURVE25519_KEYSIZE + 1] = {0};
  // use the shared curve25519 key
  memcpy(kdf_data, sharedcurvekey, sizeof sharedcurvekey);
  // and the last byte is for now hardcoded "1"
  kdf_data[(sizeof kdf_data) - 1] = '1';

  const EVP_CIPHER *cipher = EVP_aes_128_cbc();
  int keylen = EVP_BytesToKey(
    cipher, EVP_sha1(), NULL, kdf_data, sizeof kdf_data, 1,
    cipherkey, cipheriv);
  bail_require(keylen == cipher->key_len);

  BIO *benc = BIO_new(BIO_f_cipher());
  bail_null(benc);

  BIO_set_cipher(benc, cipher, cipherkey, cipheriv, 1);

  BIO *ciphertextbio = BIO_new(BIO_s_mem());
  bail_null(ciphertextbio);

  bail_require(BIO_push(benc, ciphertextbio) == benc);

  // encrypt "hello"
  const char str[] = "hello-rs";
  int retval = BIO_write(benc, str, strlen(str));
  bail_require(retval == strlen(str));
  bail_require(1 == BIO_flush(benc));

  // read out the first 4 bytes of the ciphertext
  retval = BIO_read(ciphertextbio, ciphertext, sizeof ciphertext);
  bail_require(retval == sizeof ciphertext);

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

  if(argc != 4)
  {
    printf("- Invalid parameters!!!\n");
    printf("- Usage: %s <target IP> <target port> <RS curve25519 pubkey file>\n", argv[0]);
    printf("  - RS is 'registration server'\n");
    exit(-1);
  }

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

  u_char ciphertext[4] = {0};
  bail_error(getciphertext(sharedkey, ciphertext));



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

  const int numrequiredpackets = (CURVE25519_KEYSIZE + 4) / 4;
  unsigned int count;
  for(count = 0; count < numrequiredpackets; count++)
  {
    if (count < (numrequiredpackets - 1)) {
      // use the pub key
      memcpy(&tcp->tcph_seqnum, mypubkey + (4 * count), 4);
    }
    else {
      // use the ciphertext
      memcpy(&tcp->tcph_seqnum, ciphertext, 4);
    }

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
      printf("Count #%u - sendto() is OK\n", count);
    }
    sleep(0.1);
  }

bail:
  close(sd);
  openssl_safe_free(BIO, rspubkeybio);
  return 0;
}
