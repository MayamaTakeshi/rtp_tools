all: extract_rtp_stream_payload

extract_rtp_stream_payload: main.c
	gcc -g main.c -lpcap -o extract_rtp_stream_payload

install: extract_rtp_stream_payload
	cp -f extract_rtp_stream_paylooad /usr/local/bin/


