#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdint.h>

int g_link_header_size = 0;

void process_tls_handshake(const u_char *payload, int len) {
    if (len < 44) return;
    if (payload[0] != 0x16 || payload[5] != 0x02) return;

    uint8_t session_id_length = payload[43];
    int cipher_suite_offset = 43 + 1 + session_id_length;

    if (len < cipher_suite_offset + 2) return;

    uint16_t cipher_suite_id = (payload[cipher_suite_offset] << 8) + payload[cipher_suite_offset + 1];

    if (cipher_suite_id == 0x002f) {
        printf("\nSUCCESS: Weak TLS Cipher Suite detected (ID: 0x%04x)!\n", cipher_suite_id);
    }
}

void process_ip(const u_char *packet) {
    const struct iphdr *ip = (const struct iphdr *)(packet + g_link_header_size);
    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + g_link_header_size + (ip->ihl * 4));
        if (ntohs(tcp->dest) == 4433 || ntohs(tcp->source) == 4433) {
            int ip_header_len = ip->ihl * 4;
            int tcp_header_len = tcp->doff * 4;
            const u_char *payload = (u_char *)(tcp) + tcp_header_len;
            int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
            if (payload_len > 0) {
                process_tls_handshake(payload, payload_len);
            }
        }
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len < g_link_header_size) return;

    // This logic correctly handles different header types
    if (g_link_header_size == 14) { // Ethernet
        const struct ether_header *eth = (const struct ether_header *)packet;
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) process_ip(packet);
    } else if (g_link_header_size == 4) { // Loopback
        uint32_t protocol = ntohl(*(uint32_t *)packet);
        if (protocol == AF_INET) process_ip(packet);
    } else { // Other types like Linux "cooked"
        process_ip(packet);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf); return 1;
    }

    // This switch statement correctly sets the header size for any interface
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:    g_link_header_size = 14; break;
        case DLT_NULL:      g_link_header_size = 4;  break;
        case DLT_LINUX_SLL: g_link_header_size = 16; break;
        default:
            fprintf(stderr, "Unsupported link-layer type: %s\n", pcap_datalink_val_to_name(link_type));
            return 1;
    }
    printf("Minimal TLS tester running on interface 'any' (header size: %d). Press Ctrl+C to stop.\n", g_link_header_size);

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}