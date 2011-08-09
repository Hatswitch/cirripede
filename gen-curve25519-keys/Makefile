
all: genkey

genkey: genkey.c curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	gcc -g -Wall -lcrypto -lssl -o genkey genkey.c curve25519-20050915/curve25519.a && rm -f curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519

curve25519-20050915/curve25519.h:
	(cd curve25519-20050915 && make)

curve25519-20050915/curve25519.a:
	(cd curve25519-20050915 && make)

clean:
	rm -f genkey *~ curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519
