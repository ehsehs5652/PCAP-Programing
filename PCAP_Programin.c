#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

/* Ethernet Header */
struct ethernet_header {
    unsigned char dst_mac[ETHER_ADDR_LEN];
    unsigned char src_mac[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

/* IP Header */
struct ip_header {
    unsigned char ip_header_len:4;
    unsigned char ip_version:4;
    unsigned char tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short frag_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
};

/* TCP Header */
struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char reserved:4;
    unsigned char tcp_header_len:4;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void print_http_message(const unsigned char *data, int length) {
    printf("\n[HTTP Message]\n");

    if (length <= 0) {
        printf("No TCP Payload\n");
        return;
    }

    for (int i = 0; i < length; i++) {
        if (isprint(data[i]) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printf("%c", data[i]);
        } else {
            printf(".");
        }
    }

    printf("\n");
}

void packet_handler(unsigned char *user,
                    const struct pcap_pkthdr *pkthdr,
                    const unsigned char *packet) {
    struct ethernet_header *eth;
    struct ip_header *ip;
    struct tcp_header *tcp;

    int ip_header_len;
    int tcp_header_len;
    int total_header_len;
    int payload_len;

    eth = (struct ethernet_header *)packet;

    /*
       Ethernet Type이 IPv4인지 확인
       IPv4의 EtherType은 0x0800
    */
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    ip = (struct ip_header *)(packet + ETHER_HDR_LEN);

    /*
       TCP만 처리
       TCP protocol number = 6
       UDP protocol number = 17
    */
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    ip_header_len = ip->ip_header_len * 4;

    tcp = (struct tcp_header *)(packet + ETHER_HDR_LEN + ip_header_len);

    tcp_header_len = tcp->tcp_header_len * 4;

    total_header_len = ETHER_HDR_LEN + ip_header_len + tcp_header_len;

    payload_len = pkthdr->caplen - total_header_len;

    printf("========================================\n");

    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->src_mac);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->dst_mac);
    printf("\n\n");

    printf("[IP Header]\n");
    printf("Source IP       : %s\n", inet_ntoa(ip->src_ip));
    printf("Destination IP  : %s\n", inet_ntoa(ip->dst_ip));
    printf("IP Header Len   : %d bytes\n\n", ip_header_len);

    printf("[TCP Header]\n");
    printf("Source Port     : %d\n", ntohs(tcp->src_port));
    printf("Destination Port: %d\n", ntohs(tcp->dst_port));
    printf("TCP Header Len  : %d bytes\n", tcp_header_len);

    if (payload_len > 0) {
        const unsigned char *payload = packet + total_header_len;
        print_http_message(payload, payload_len);
    } else {
        printf("\n[HTTP Message]\n");
        printf("No TCP Payload\n");
    }

    printf("========================================\n\n");
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
