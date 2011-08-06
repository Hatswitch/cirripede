
all: register

register: register.c curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	gcc -g -Wall -lm -lcrypto -lssl -o register register.c curve25519-20050915/curve25519.a && rm -f curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519

curve25519-20050915/curve25519.h:
	(cd curve25519-20050915 && make)

curve25519-20050915/curve25519.a:
	(cd curve25519-20050915 && make)

clean:
	rm -f register *~ curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519
