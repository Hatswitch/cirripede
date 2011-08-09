#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "curve25519-20050915/curve25519.h"

#define CURVE25519_KEYSIZE (32)

void gensecretkey(unsigned char secret[CURVE25519_KEYSIZE])
{
  int i = 0;
  for (; i < CURVE25519_KEYSIZE; i++) {
    if (1 != RAND_bytes(secret + i, 1)) {
      puts("error generating random bytes for secret key");
      exit(-1);
    }
  }
  /* secret[0] &= 248; */
  secret[31] &= 127; /* keep this line */
  /* secret[31] |= 64; */
}

/* return 0 on success */
int computepublickey(unsigned char pub[CURVE25519_KEYSIZE],
                     const unsigned char secret[CURVE25519_KEYSIZE],
                     const int basepoint /* either 6 or 3 */
  )
{
  if (basepoint == 6) {
    static const unsigned char basepoint6[CURVE25519_KEYSIZE] = {6};
    curve25519(pub,secret, basepoint6);
    return 0;
  }
  else if (basepoint == 3) {
    static const unsigned char basepoint3[CURVE25519_KEYSIZE] = {3};
    curve25519(pub,secret, basepoint3);
    return 0;
  }
  else {
    printf("basepoint must be 6 or 3\n");
    return 1; // error
  }
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

  static const int basepoints[] = {6, 3};
  int i = 0;
  for (i = 0; i < sizeof (basepoints) / sizeof(basepoints[0]); ++i) {
    const int basepoint = basepoints[i];

    unsigned char mysecret[32] = {0};
    unsigned char mypublic[32] = {0};
    gensecretkey(mysecret);
    computepublickey(mypublic, mysecret, basepoint);

    FILE* file;
    size_t numwritten;

    char path[80];
    sprintf(path, "secret-base%u", basepoint);
    file = fopen(path, "wb");
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

    sprintf(path, "public-base%u", basepoint);
    file = fopen(path, "wb");
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
  }
  return 0;
}
