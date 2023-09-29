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

struct linked_list;

struct linked_list {
	uint32_t ip_src;
	uint32_t ip_dst;
	u_short sport;
	u_short dport;
	int payload_type;
	int count;

	struct timeval first_tv;
	struct timeval last_tv;

	struct linked_list *next;
} linked_list;

struct linked_list *g_list = 0;

struct linked_list *find(uint32_t ip_src, uint32_t ip_dst, u_short sport, u_short dport, struct linked_list *c, struct timeval tv) {
	if(!c) return 0;

	if(c->ip_src == ip_src && c->ip_dst == ip_dst && c->sport == sport && c->dport == dport) return c;

	return find(ip_src, ip_dst, sport, dport, c->next, tv);
}

struct linked_list *new_item(uint32_t ip_src, uint32_t ip_dst, u_short sport, u_short dport, int payload_type, struct timeval tv) {
	struct linked_list *item = malloc(sizeof(struct linked_list));
	item->ip_src = ip_src;
	item->ip_dst = ip_dst;
	item->sport = sport;
	item->dport = dport;
	item->payload_type = payload_type;
	item->first_tv = tv;

	item->next = 0;

	if(!g_list) {
		g_list = item;
	} else {
		item->next = g_list;
		g_list = item;
	}

	return item;
}

struct linked_list *get(uint32_t ip_src, uint32_t ip_dst, u_short sport, u_short dport, int payload_type, struct timeval tv) {
	struct linked_list *item = find(ip_src, ip_dst, sport, dport, g_list, tv);
	if(item) {
		return item;
	}
	return new_item(ip_src, ip_dst, sport, dport, payload_type, tv);
}

void split_ipv4(u_char *octects, uint32_t ip) {
	uint32_t hip = ntohl(ip);

	octects[3] = hip & 0xFF;
	octects[2] = hip >> 8 & 0xFF;
	octects[1] = hip >> 16 & 0xFF;
	octects[0] = hip >> 24 & 0xFF;
}

void dump_stats(struct linked_list *c) {
	if(!c) return;

	u_char src_ip[4];
	u_char dst_ip[4];

	split_ipv4(src_ip, c->ip_src);
	split_ipv4(dst_ip, c->ip_dst);

	printf("%u %d.%d.%d.%d %hu %d.%d.%d.%d %hu %i %lld %lld\n",
		c->count,

		src_ip[0],
		src_ip[1],
		src_ip[2],
		src_ip[3],

		ntohs(c->sport),

		dst_ip[0],
		dst_ip[1],
		dst_ip[2],
		dst_ip[3],

		ntohs(c->dport),

		c->payload_type,

		(long long)(c->first_tv.tv_sec) * 1000 + (long long)(c->first_tv.tv_usec) / 1000,
		(long long)(c->last_tv.tv_sec) * 1000 + (long long)(c->last_tv.tv_usec) / 1000
	);

	dump_stats(c->next);
}

void usage(char *app_name) {
	printf("\n"\
"Usage: %s pcap_file\n"\
"Ex:    %s test.pcap\n"\
, app_name, app_name);
}


int main(int argc, char *argv[]) {
	int c;
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments. Expected: 1, Received: %d\n", argc-1);
		usage(argv[0]);
		exit(1);
	}

	char *pcap_file = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *descr = pcap_open_offline(pcap_file, errbuf);

	if(!descr) {
		fprintf(stderr, "pcap_open_offline() failed %s\n", errbuf);
		exit(1);
	}

	int dl = pcap_datalink(descr);

	if(DLT_EN10MB != dl && DLT_LINUX_SLL != dl) {
		fprintf(stderr, "datalink isn't either Ethernet or Linux cooked SLL. Aborting.\n");
		exit(1);
	}

	struct linked_list *item;

	while(1) {
		struct pcap_pkthdr *header;
		const u_char *data;

		int res = pcap_next_ex(descr, &header, &data);
		if(-1 == res) {
			fprintf(stderr, "pcap_next_ex failed\n");
			exit(1);
		} else if(-2 == res) {
			// no more packets
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
			//fprintf(stderr, "Ignoring non-RTP packet.\n");
			continue;
		}

		int payload_type = rtp_h[1] & 0x7F;

		uint16_t seqnum = (rtp_h[2] * 256 + rtp_h[3]);

		int marker = (rtp_h[1] >> 7) & 0x1;

		item = get(ip_h->ip_src, ip_h->ip_dst, udp_h->source, udp_h->dest, payload_type, header->ts);
		item->last_tv = header->ts;
		item->count++;
	}

	pcap_close(descr);

	printf("PACKET_COUNT SRC_IP SRC_PORT DST_IP DST_PORT PAYLOAD_TYPE FIRST_PACKET_EPOCH LAST_PACKET_EPOCH\n");
	dump_stats(g_list);
	
	return 0;
}


