#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <iostream>
#include <string.h>
#include <list>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define buf_size 256
#define packet_size 1486

int get_par_content(char *buf, char* result);

using namespace std;
list<char*> block_list;

void block_set(list<char*>* block_list) {
	FILE *fd;
	char buf[buf_size];
	char data[buf_size];

	if ((fd = fopen("list.txt", "r")) == NULL) {
		exit(1);
	}
	memset(buf, 0, buf_size);
	memset(data, 0, buf_size);

	while (fgets(buf, buf_size, fd) != NULL) { // single line read. 0a 
		if (get_par_content(buf, data) == 0)
			continue;
		//printf("%s", data);
		char* tmps = new char[buf_size];
		memset(tmps, 0, buf_size);
		memcpy(tmps, data, buf_size);
		block_list->push_back(tmps);
		memset(data, 0, buf_size);
	} // 비교하기 위해 list에 저장해놓자.
	fclose(fd);
}

int get_par_content(char *buf, char* result) { // 1 - success , 0 - fail
	string tmp = buf;
	int cnt = 0;
	string con = "content:\"";
	if (tmp.find("#") != -1) return 0;
	if ((cnt = tmp.find(con)) != string::npos) {
		tmp.erase(0, cnt + con.size());
		if ((cnt = tmp.find("\"")) != string::npos) {
			tmp.erase(cnt, tmp.size());
			//tmp.append("\n");
			memcpy(result, tmp.data(), cnt);
			return 1;
		}
	}
	return 0;
}
void packet_show(const unsigned char* packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0 && i != 0) {
			printf("  ");
			for (int j = -16; j <= -1; j++) {
				if (j == -8)
					printf("  ");
				if (isprint(*(packet + i + j)))
					printf("%c", *(packet + i + j));
				else
					printf(".");
			}
			printf("\n");
		}
		if (i % 8 == 0)
			printf("  ");
		printf("%02x ", *(packet + i));
	}
	for (i = 0; i<16 - (len % 16); i++) {
		printf("   ");
		if (i % 8 == 0)
			printf("  ");
	}
	for (int i = (len / 16) * 16; i<len; i++) {
		if (i % 8 == 0 && i % 16 != 0)
			printf("  ");
		if (isprint(*(packet + i)))
			printf("%c", *(packet + i));
		else
			printf(".");
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

int header_check(struct nfqnl_msg_packet_hdr *header, unsigned char *pkt_data, int p1, int p2, int p3) {
	int check = true;
	struct libnet_ipv4_hdr *ipv4;
	struct libnet_tcp_hdr *tcph;
	uint16_t protocol = ntohs(header->hw_protocol); // ether type

	if (protocol != p1) // ether type check
		check = false;

	ipv4 = (struct libnet_ipv4_hdr*)(pkt_data);
	if (ipv4->ip_p != p2) { // tcp = 0x06
		check = false;
	}
	else if (ipv4->ip_p == p2) {
		int ip_header_size = (ipv4->ip_hl * 4);
		tcph = (struct libnet_tcp_hdr*)(pkt_data + ip_header_size);

		int tcp_header_size = (tcph->th_off * 4);
		int data_start_off = ip_header_size + tcp_header_size;
		int data_size = ntohs(ipv4->ip_len) - ip_header_size - tcp_header_size;
		uint16_t s_port = ntohs(tcph->th_sport);
		uint16_t d_port = ntohs(tcph->th_dport);
		if ((s_port != p3) && (d_port != p3)) {
			check = false;
		}
	}
	//printf("%02x %02x ", ipv4->ip_p, p2);
	return check;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
	unsigned char *packet_data; // packet_data
	uint32_t id = 0; // IP header, Protocol
	uint32_t len = 0;
	uint16_t protocol = 0;
	struct nfqnl_msg_packet_hdr *header;
	bool check = false;
	list <char*>::iterator c1_Iter; // 리스트 탐색용 변수

	if ((header = nfq_get_msg_packet_hdr(nfa))) {
		id = ntohl(header->packet_id);
	}
	len = nfq_get_payload(nfa, &packet_data);
	//protocol = ntohs(header->hw_protocol);

	check = header_check(header, packet_data, ETHERTYPE_IP, IPPROTO_TCP,80);
	//if (header_check(header, packet_data, ETHERTYPE_IP, IPPROTO_TCP,80) == true) // tcp check
	//	check = true;

	if(check == true){ // 80port[HTTP]
		string s_data(reinterpret_cast<char const *>(packet_data), len); // string 객체에 담기
		for (c1_Iter = block_list.begin(); c1_Iter != block_list.end(); ++c1_Iter) {
			if (s_data.find((string)*c1_Iter) != string::npos) {
				printf("[ %s ] block. \n", *c1_Iter);
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, len, packet_data);

	/* IP, TCP, HTTP Parsing -> list check(algorithm) -> Harmful site block
	//						  -> else ACCEPT
	// List File open -> Read -> Check.
	// Tokenizer..?? .
	*/
}

int main(int argc, char **argv)
{
	// gcc -o net net -lnetfileter_queue
	// iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));
	block_set(&block_list);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received %s\n",block_list.front());
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		* are sent from kernel-space, the socket buffer that we use
		* to enqueue packets may fill up returning ENOBUFS. Depending
		* on your application, this error may be ignored. Please, see
		* the doxygen documentation of this library on how to improve
		* this situation.
		*/
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	* it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
