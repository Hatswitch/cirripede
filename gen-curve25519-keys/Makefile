
all: genkey

genkey: genkey.c curve25519-20050915/curve25519.a curve25519-20050915/curve25519.h
	gcc -Wall -lcrypto -lssl -o genkey genkey.c curve25519-20050915/curve25519.a

curve25519-20050915/curve25519.a:
	(cd curve25519-20050915 && make)

clean:
	rm -f genkey *~
