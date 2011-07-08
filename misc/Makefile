all: countpackets

countpackets: countpackets.cc common.hpp
	g++ -g -Wall -lpcap -o countpackets countpackets.cc

clean:
	rm -f countpackets *~
