all: detect_rtp_streams

detect_rtp_streams: main.c
	gcc -g main.c -lpcap -o detect_rtp_streams

install: detect_rtp_streams
	cp -f detect_rtp_streams /usr/local/bin/


