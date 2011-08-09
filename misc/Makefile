all: countpackets measureSYNInterarrival addregistration

countpackets: countpackets.cc common.hpp
	g++ -g -Wall -lpcap -o countpackets countpackets.cc

measureSYNInterarrival: measureSYNInterarrival.cc common.hpp
	g++ -g -Wall -lpcap -o measureSYNInterarrival measureSYNInterarrival.cc

clean:
	rm -f countpackets measureSYNInterarrival addregistration *~ \
	curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out \
	curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check \
	curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h \
	curve25519-20050915/test-curve25519






LBITS := $(shell getconf LONG_BIT)
ifeq ($(LBITS),64)
	CFLAGS="-DUSE64"
addregistration: addregistration.cc common.hpp ../curve25519-donna-c64.c
	g++ -DUSE64 -g -Wall -lm -lpcap -lcrypto -o addregistration addregistration.cc

else
  # do 32 bit stuff here
addregistration: addregistration.cc common.hpp \
	curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	g++ -g -Wall -lm -lpcap -lcrypto -o addregistration addregistration.cc \
		curve25519-20050915/curve25519.a && \
		rm -f curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out \
		curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check \
		curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h \
		curve25519-20050915/test-curve25519

curve25519-20050915/curve25519.h:
	(cd curve25519-20050915 && make)

curve25519-20050915/curve25519.a:
	(cd curve25519-20050915 && make)

endif
