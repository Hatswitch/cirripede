all: countpackets measureSYNInterarrival

countpackets: countpackets.cc common.hpp
	g++ -g -Wall -lpcap -o countpackets countpackets.cc

measureSYNInterarrival: measureSYNInterarrival.cc common.hpp
	g++ -g -Wall -lpcap -o measureSYNInterarrival measureSYNInterarrival.cc

clean:
	rm -f countpackets measureSYNInterarrival *~
