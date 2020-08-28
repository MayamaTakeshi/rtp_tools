#include "pcap.h"
#include "sys/socket.h"
#include "net/ethernet.h"
#include "netinet/ip.h"
#include "netinet/in.h"
#include "netinet/if_ether.h"
#include "netinet/udp.h"
#include "arpa/inet.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <errno.h>

#include <unistd.h> /* For getopt */

struct dlt_linux_sll {
	u_short packet_type;
	u_short ARPHRD;
	u_short slink_length;
	u_char bytes[8];
	u_short ether_type;
};

struct ip_header {
	u_char ip_version_headerlength; // version << 4 | header length >> 2
	u_char ip_tos; //Type of service
	u_short ip_len; // total length
	u_short ip_id; // identification
	u_short ip_off; //fragment offset field
	
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	u_int ip_src;
	u_int ip_dst;
};


#define DELAY_THRESHOLD 50
#define TIME_SPAN_LIMIT 24 * 60 * 60 * 1000

#define SILENCE_PAYLOAD_SIZE_ULAW 160
#define SILENCE_PAYLOAD_SIZE_ALAW 160
#define SILENCE_PAYLOAD_SIZE_GSM  33
#define SILENCE_PAYLOAD_SIZE_G729 10


char silence_ulaw[SILENCE_PAYLOAD_SIZE_ULAW];
char silence_alaw[SILENCE_PAYLOAD_SIZE_ALAW];
char silence_gsm[SILENCE_PAYLOAD_SIZE_GSM] = {0xdb, 0x6c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char silence_g729[SILENCE_PAYLOAD_SIZE_G729] = {0x78, 0x52, 0x80, 0xa0, 0x00, 0xfa, 0xc2, 0x00, 0x07, 0xd6};


void prepare_silence() {
	for(int i=0; i<SILENCE_PAYLOAD_SIZE_ULAW; i++) {
		silence_ulaw[i] = 0xff;
	}
	for(int i=0; i<SILENCE_PAYLOAD_SIZE_ALAW; i++) {
		silence_alaw[i] = 0xd5;
	}
}


void write_silence(FILE *fd, int payload_type) {
	int written;
	int size;
	if(payload_type == 0) {
		size = SILENCE_PAYLOAD_SIZE_ULAW;
		written = fwrite(silence_ulaw, 1, size, fd);
	} else if(payload_type == 8) {
		size = SILENCE_PAYLOAD_SIZE_ALAW;
		written = fwrite(silence_alaw, 1, size, fd);
	} else if(payload_type == 3) {
		size = SILENCE_PAYLOAD_SIZE_GSM;
		written = fwrite(silence_gsm, 1, size, fd);
	} else if(payload_type == 18) {
		size = SILENCE_PAYLOAD_SIZE_G729;
		written = fwrite(silence_g729, 1, size, fd);
	} else {
		printf("Cannot generate silence payload. Unsupported payload_type %i\n", payload_type);
		exit(1);
	}

	if(written != size) {
		printf("fwrite() for silence failed. written=%i size=%i\n", written, size);
		exit(1);	
	}

	fflush(fd);
}

void write_payload(FILE *fd, u_char *payload, int size) {
	int written = fwrite(payload, 1, size, fd);

	if(written != size) {
		printf("fwrite() failed. written=%i size=%i\n", written, size);
		exit(1);
	}

	fflush(fd);
} 


void usage(char *app_name) {
	printf("\n"\
"Usage: %s pcap_file src_ip src_port dst_ip dst_port payload_type codec start_stamp end_stamp stream.raw\n"\
"Ex:    %s test.pcap 192.168.2.1 10000 192.168.2.2 20000 0 pcmu 1597619570222 1597619590487 out_file\n"\
"\n"\
"Details:\n"\
"      - start_stamp and end_stamp should be epoch in milliseconds\n"\
"      - codec: pcmu | pcma | gsm | g.729\n"\
, app_name, app_name);
}


int main(int argc, char *argv[]) {
	int c;
	if(argc != 11) {
		printf("Invalid number of arguments. Expected: 10, Received: %d\n", argc-1);
		usage(argv[0]);
		exit(1);
	}

	char *pcap_file = argv[1];
	char *src_ip = argv[2];
	char *src_port = argv[3];
	char *dst_ip = argv[4];
	char *dst_port = argv[5];
	char *payload_type_str = argv[6];
	char *codec = argv[7];
	char *start_stamp_str = argv[8];
	char *end_stamp_str = argv[9];
	char *out_file = argv[10];

	int payload_type = atoi(payload_type_str);
	unsigned long start_stamp = strtoul(start_stamp_str, NULL, 10); 
	unsigned long end_stamp = strtoul(end_stamp_str, NULL, 10); 

	if(start_stamp > end_stamp) {
		printf("start_stamp=%lu is older than end_stamp=%lu. Aborting.\n", start_stamp, end_stamp);
		exit(1);
	}

	if(end_stamp - start_stamp > TIME_SPAN_LIMIT) {
		printf("end_stamp - start_stamp = %lu. Too large time span (TIME_SPAN_LIMIT=%i). Aborting.\n", end_stamp - start_stamp, TIME_SPAN_LIMIT);
		exit(1);
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *descr = pcap_open_offline(pcap_file, errbuf);

	if(!descr) {
		printf("pcap_open_offline() failed %s\n", errbuf);
		exit(1);
	}

	int dl = pcap_datalink(descr);

	if(DLT_EN10MB != dl && DLT_LINUX_SLL != dl) {
		printf("datalink isn't either Ethernet or Linux coonked SLL. Aborting.\n");
		exit(1);
	}

	struct bpf_program fp;

	char filter[2048];
	sprintf(filter, "src host %s and src port %s and dst host %s and dst port %s", src_ip, src_port, dst_ip, dst_port);
	//printf("filter=%s\n", filter);

    if(pcap_compile(descr, &fp, filter ,0 , 0) == -1) {
		printf("Error calling pcap_compile\n");
		exit(1);
	}

	if(pcap_setfilter(descr, &fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter, pcap_geterr(descr));
		exit(1);
	}

	prepare_silence();

	FILE *out = fopen(out_file, "wb");

	unsigned long last_ts = start_stamp;

	int count = 0;

	while(1) {
		struct pcap_pkthdr *header;
		const u_char *data;

		int res = pcap_next_ex(descr, &header, &data);
		if(-1 == res) {
			printf("pcap_next_ex failed\n");
			exit(1);
		} else if(-2 == res) {
			// no more packets
			break;
		}	

        unsigned long ts = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
		//printf("ts=%lu\n", ts);

        if(ts < start_stamp) {
            continue;
        }

        if(ts > end_stamp) {
            break;
        }

		struct ip_header *ip_h;
		struct udphdr *udp_h;
		u_char *rtp_h;

		if(DLT_EN10MB == dl) {
			ip_h = (struct ip_header*)(data + sizeof(struct ether_header));
			u_int size_ip = ((ip_h)->ip_version_headerlength & 0x0f)*4;
			udp_h = (struct udphdr*)(data + sizeof(struct ether_header) + size_ip);
		} else {
			//Linux SLL cooked
			ip_h = (struct ip_header*)(data + sizeof(struct dlt_linux_sll));
			u_int size_ip = (ip_h->ip_version_headerlength & 0x0f)*4;
			udp_h = (struct udphdr*)(data + sizeof(struct dlt_linux_sll) + size_ip);
		}

		rtp_h = ((u_char*)udp_h + 8);

		int ver = (rtp_h[0] >> 6) & 0x02;
		if(ver != 2) {
			// not RTP packet
            printf("Ignoring non-RTP packet.\n");
			continue;
		}

		int pt = rtp_h[1] & 0x7F;
        if(pt != payload_type) {
            printf("Ignoring packet with unpexected payload_type=%d\n", pt);
			continue;
		}

		uint16_t seqnum = (rtp_h[2] * 256 + rtp_h[3]);
		//printf("seqnum: %u\n", seqnum);

		int marker = (rtp_h[1] >> 7) & 0x1;
		if(marker == 1) {
			printf("marker_bit set\n");
		}

        unsigned long diff = ts - last_ts;

        if(diff > DELAY_THRESHOLD) {
            unsigned silence_packets = diff / 20;

            for(int i=0 ; i<silence_packets ; ++i) {
                printf("adding silence for %lu %u\n", last_ts, seqnum);
                write_silence(out, payload_type);
                count++;
            } 
        }

		int size = header->caplen - 54;
        // rtp header without extensions is 12 bytes
		write_payload((FILE*)out, &rtp_h[12], size);

		count++;

        last_ts = ts;
	}

    // write silence at the end if necessary
    int expected = (end_stamp - start_stamp) / 20;
    printf("expected=%i count=%i\n", expected, count);
    for(int i=0 ; i<(expected - count) ; ++i) {
        printf("adding post silence\n");
        write_silence(out, payload_type);
    }

	pcap_close(descr);
	fclose(out);	
	
	return 0;
}


