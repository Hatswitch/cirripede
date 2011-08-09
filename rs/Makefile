#all: rs rs-nothread

LBITS := $(shell getconf LONG_BIT)
ifeq ($(LBITS),64)
	CFLAGS="-DUSE64"

rs: rs.cc ../curve25519-donna-c64.c
	g++ -DUSE64 -g -Wall -lcrypto -lpcap -llog4cxx -lboost_thread -o rs rs.cc

rs-nothread: rs-nothread.cc ../curve25519-donna-c64.c
	g++ -DUSE64 -g -Wall -lcrypto -lpcap -llog4cxx -o rs-nothread rs-nothread.cc

else
  # do 32 bit stuff here
rs: rs.cc curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	g++ -g -Wall -lcrypto -lboost_thread -llog4cxx -lpcap -o rs rs.cc curve25519-20050915/curve25519.a && rm -f curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519

rs-nothread: rs-nothread.cc curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	g++ -g -Wall -lcrypto -lpcap -llog4cxx -o rs-nothread rs-nothread.cc curve25519-20050915/curve25519.a && rm -f curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519

curve25519-20050915/curve25519.h:
	(cd curve25519-20050915 && make)

curve25519-20050915/curve25519.a:
	(cd curve25519-20050915 && make)

endif

clean:
	rm -f rs rs-nothread *~ curve25519-20050915/curve25519.h curve25519-20050915/x86cpuid.out curve25519-20050915/curve25519.impl curve25519-20050915/curve25519.impl.check curve25519-20050915/x86cpuid curve25519-20050915/curve25519.impl.check.h curve25519-20050915/test-curve25519
