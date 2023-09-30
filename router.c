#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "string.h"

#define ETH_ADRLEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define MAX_ENTRIES 100000
#define ECHO_REQUEST 8
#define ECHO_REPLY 0
#define ICMP_PROT 1
#define DEST_UNREACH 3
#define TIME_EXCEEDED 11
#define FIRST_BYTES 8
#define STD_TTL 64

struct route_table_entry *rtable;
int rlen;

struct arp_entry *arptable;
int arplen;

void icmp_dropped_packet(int interface, char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t type)
{
	char *data = malloc(sizeof(struct iphdr) + FIRST_BYTES);
	DIE(!data, "malloc failed");
	memcpy(data, buf + sizeof(struct ether_header), sizeof(struct iphdr) + FIRST_BYTES);

	// add IP header and first 8 bytes of payload of dropped packet
	strcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data);

	// change MAC addresses
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(interface, eth_hdr->ether_shost);

	// change IP addresses
	ip_hdr->daddr = ip_hdr->saddr;
	struct in_addr ip;
	inet_aton(get_interface_ip(interface), &ip);
	ip_hdr->saddr = ip.s_addr;

	// recalculate IP checksum
	ip_hdr->ttl = STD_TTL;
	ip_hdr->check = 0;
	ip_hdr->protocol = ICMP_PROT;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + FIRST_BYTES);
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// update ICMP header
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	int len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + FIRST_BYTES;

	free(data);

	// send packet
	send_to_link(interface, buf, len);
}

void icmp_echo(int interface, char *buf, int len, struct iphdr *ip_hdr)
{
	// check if ICMP
	if (ip_hdr->protocol != ICMP_PROT)
		return;

	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// check if ICMP echo request
	if (icmp_hdr->type != ECHO_REQUEST)
		return;

	// check checksum
	uint16_t check = ntohs(icmp_hdr->checksum);
	icmp_hdr->checksum = 0;
	if (check != checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)))
		return;

	// change type
	icmp_hdr->type = ECHO_REPLY;

	// recalculate checksum
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// send packet
	send_to_link(interface, buf, len);
}

struct arp_entry *get_arp_nexthop(uint32_t ip) {
  for (int i = 0; i < arplen; i++)
    if (arptable[i].ip == ip)
      return &arptable[i];

  return NULL;
}

// qsort beforehand + binary search
struct route_table_entry *lpm(uint32_t ip) {
	int l = 0, r = rlen - 1, m;
	struct route_table_entry *route = NULL;

	while (l <= r) {
		m = l + (r - l) / 2;

		if ((ip & rtable[m].mask) == rtable[m].prefix) {
			if (!route || route->mask < rtable[m].mask)
				route = &rtable[m];
			r = m - 1;
		} else if ((ip & rtable[m].mask) < rtable[m].prefix) {
			l = m + 1;
		}
		else {
			r = m - 1;
		}
	}

	return route;
}

void handle_ip(int interface, char *buf, int len, struct ether_header *eth_hdr)
{
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

	// check checksum
	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	if (check != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
		return;

	// check TTL
	if (ip_hdr->ttl <= 1) {
		icmp_dropped_packet(interface, buf, eth_hdr, ip_hdr, TIME_EXCEEDED);
		return;
	}

	// decrement TTL
	ip_hdr->ttl--;

	// recompute checksum
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// check destination address
	struct in_addr ip;
	inet_aton(get_interface_ip(interface), &ip);
	if (ip_hdr->daddr == ip.s_addr) {
		icmp_echo(interface, buf, len, ip_hdr);
		return;
	}

	// get best route for packet
	struct route_table_entry *route = lpm(ip_hdr->daddr);
	if (!route) {
		icmp_dropped_packet(interface, buf, eth_hdr, ip_hdr, DEST_UNREACH);
		return;
	}

	// check ARP table
	struct arp_entry *next_hop = get_arp_nexthop(route->next_hop);
	if (!next_hop) {
		// send ARP request
		return;
	}

	// update source and destination MAC addresses
	get_interface_mac(route->interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, next_hop->mac, sizeof(eth_hdr->ether_dhost));

	// send packet
    send_to_link(route->interface, buf, len);
}

int cmp(const void *x, const void *y) 
{
  struct route_table_entry *r1 = (struct route_table_entry *)x;
  struct route_table_entry *r2 = (struct route_table_entry *)y;

  return (r1->prefix != r2->prefix) ? (r1->prefix < r2->prefix) : (r2->mask > r1->mask);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN] = {0};

	// Do not modify this line
	init(argc - 2, argv + 2);

	// create routing table
	rtable = malloc(MAX_ENTRIES * sizeof(struct route_table_entry));
	DIE(!rtable, "routing table malloc failed");
	rlen = read_rtable(argv[1], rtable);
	qsort(rtable, rlen, sizeof(struct route_table_entry), cmp);

	// create ARP table
	arptable = malloc(MAX_ENTRIES * sizeof(struct arp_entry));
  	DIE(!arptable, "ARP table malloc failed");
	// parse static ARP table
	arplen = parse_arp_table("arp_table.txt", arptable);

	int interface;
	size_t len;
	uint8_t *mac = malloc(ETH_ADRLEN * sizeof(uint8_t));

	while (1) {
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// check MAC destination address 
		DIE(!mac, "mac malloc failed");
		get_interface_mac(interface, mac);
		if (memcmp(eth_hdr->ether_dhost, mac, sizeof(eth_hdr->ether_dhost)) != 0)
		 	continue;

		// check ether type
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			handle_ip(interface, buf, len, eth_hdr);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// handle ARP
		}

		memset(buf, 0, len);
	}

	free(mac);
	free(rtable);
	free(arptable);
}
