#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "curve25519-20050915/curve25519.h"

void gensecretkey(unsigned char secret[32])
{
  int i = 0;
  for (; i < 32; i++) {
    if (1 != RAND_bytes(secret + i, 1)) {
      puts("error generating random bytes for secret key");
      exit(-1);
    }
  }
  secret[0] &= 248;
  secret[31] &= 127;
  secret[31] |= 64;
}

void computepublickey(unsigned char pub[32], const unsigned char secret[32])
{
  static const unsigned char basepoint[32] = {9};
  curve25519(pub,secret,basepoint);
}

void usage(const char *progname)
{
  printf(
    "generate a pair of curve25510 secret and public keys, placed into\n" \
    "'secret' and 'public' files.\n\n" \
    "Usage: %s\n",
    progname);
  return;
}

int main(int argc, char *argv[])
{
  SSL_library_init();
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OpenSSL_add_all_algorithms();

  if (argc != 1) {
    usage(argv[0]);
    return -1;
  }

  unsigned char mysecret[32] = {0};
  unsigned char mypublic[32] = {0};
  gensecretkey(mysecret);
  computepublickey(mypublic, mysecret);

  FILE* file;
  size_t numwritten;

  file = fopen("secret", "wb");
  if (!file) {
    puts("can't open secret file");
    return -1;
  }
  numwritten = fwrite(mysecret, 1, sizeof mysecret, file);
  if (numwritten != sizeof mysecret) {
    puts("error writing to secret file");
    return -1;
  }
  fclose(file);

  file = fopen("public", "wb");
  if (!file) {
    puts("can't open public file");
    return -1;
  }
  numwritten = fwrite(mypublic, 1, sizeof mypublic, file);
  if (numwritten != sizeof mypublic) {
    puts("error writing to public file");
    return -1;
  }
  fclose(file);

  puts("successful.");
  return 0;
}
