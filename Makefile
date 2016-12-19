all: dissector 

dissector:
	gcc -g -Wall -o dissector dissector.c -lpcap

clean:
	rm dissector good-dissector sample1.pcap sample2.pcap

