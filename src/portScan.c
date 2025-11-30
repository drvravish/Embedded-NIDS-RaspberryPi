#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

// ================== CONFIGURATION ==================
#define MAX_TRACKED_IPS 1024
#define PORT_SCAN_THRESHOLD 15
#define PORT_SCAN_TIME_WINDOW 10
#define ALERT_COOLDOWN 60
#define IP_IDLE_TIMEOUT 300
#define DEFAULT_INTERFACE "any" // Use "any" for testing, "eth0" for deployment
#define STATE_CLEANUP_INTERVAL 5 

// ================== DATA STRUCTURES ==================

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t ports[MAX_TRACKED_IPS];
    int port_count;
    time_t window_start_time;
    time_t last_alert_time;
    time_t last_seen;
} PortScanTracker;

// ================== GLOBAL VARIABLES ==================
pcap_t *pcap_handle = NULL;
volatile sig_atomic_t running = 1;
int g_link_header_size = 0;

PortScanTracker port_scan_list[MAX_TRACKED_IPS];
int port_scan_list_size = 0;

// ================== FUNCTION DECLARATIONS ==================
void log_event(const char *message);
void cleanup_state();
void process_port_scan(const char *src_ip, const char *dst_ip, uint16_t dst_port, const struct tcphdr *tcp);
void process_ip(const u_char *packet);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void shutdown_handler(int signum);

// ================== IMPLEMENTATION ==================

void log_event(const char *message) {
    FILE *log = fopen("port_scan.log", "a");
    if (log) {
        time_t now = time(NULL);
        char time_str[26];
        ctime_r(&now, time_str);
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log, "[%s] %s\n", time_str, message);
        fclose(log);
    }
    printf("%s\n", message);
    fflush(stdout);
}

void cleanup_state() {
    time_t now = time(NULL);
    int i = 0;
    while (i < port_scan_list_size) {
        if (now - port_scan_list[i].last_seen > IP_IDLE_TIMEOUT) {
            port_scan_list[i] = port_scan_list[port_scan_list_size - 1];
            port_scan_list_size--;
        } else {
            i++;
        }
    }
}

void process_port_scan(const char *src_ip, const char *dst_ip, uint16_t dst_port, const struct tcphdr *tcp) {
    // Only look for the start of a connection (SYN packet)
    if (!(tcp->syn && !tcp->ack)) {
        return;
    }

    time_t now = time(NULL);
    int found_entry = -1;
    for (int i = 0; i < port_scan_list_size; i++) {
        if (strcmp(port_scan_list[i].src_ip, src_ip) == 0 && strcmp(port_scan_list[i].dst_ip, dst_ip) == 0) {
            found_entry = i;
            break;
        }
    }

    if (found_entry == -1) {
        if (port_scan_list_size >= MAX_TRACKED_IPS) return;
        found_entry = port_scan_list_size++;
        snprintf(port_scan_list[found_entry].src_ip, INET_ADDRSTRLEN, "%s", src_ip);
        snprintf(port_scan_list[found_entry].dst_ip, INET_ADDRSTRLEN, "%s", dst_ip);
        port_scan_list[found_entry].port_count = 0;
        port_scan_list[found_entry].window_start_time = now;
        port_scan_list[found_entry].last_alert_time = 0;
        memset(port_scan_list[found_entry].ports, 0, sizeof(port_scan_list[found_entry].ports));
    }

    PortScanTracker *target = &port_scan_list[found_entry];
    target->last_seen = now;

    if (now - target->window_start_time > PORT_SCAN_TIME_WINDOW) {
        target->window_start_time = now;
        target->port_count = 0;
        memset(target->ports, 0, sizeof(target->ports));
    }

    bool port_already_scanned = false;
    for (int i = 0; i < target->port_count; i++) {
        if (target->ports[i] == dst_port) {
            port_already_scanned = true;
            break;
        }
    }

    if (!port_already_scanned && target->port_count < MAX_TRACKED_IPS) {
        target->ports[target->port_count++] = dst_port;
    }

    if (target->port_count >= PORT_SCAN_THRESHOLD && (now - target->last_alert_time > ALERT_COOLDOWN)) {
        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg), "ALERT: Port Scan detected! %s is scanning %s. %d unique ports in %d seconds.", target->src_ip, target->dst_ip, target->port_count, PORT_SCAN_TIME_WINDOW);
        log_event(alert_msg);
        target->last_alert_time = now;
    }
}

void process_ip(const u_char *packet) {
    const struct iphdr *ip = (const struct iphdr *)(packet + g_link_header_size);
    
    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + g_link_header_size + (ip->ihl * 4));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));
        uint16_t dst_port = ntohs(tcp->dest);
        
        process_port_scan(src_ip, dst_ip, dst_port, tcp);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len < g_link_header_size) return;

    if (g_link_header_size == 14) { // Ethernet
        const struct ether_header *eth = (const struct ether_header *)packet;
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) process_ip(packet);
    } else { // Loopback, Linux SLL, etc.
        process_ip(packet);
    }
}

void shutdown_handler(int signum) {
    log_event("Interrupt signal received, shutting down...");
    running = 0;
    if (pcap_handle) pcap_breakloop(pcap_handle);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    FILE *log = fopen("port_scan.log", "w"); 
    if (log) fclose(log);

    log_event("Port Scan Detector starting...");
    signal(SIGINT, shutdown_handler);

    pcap_handle = pcap_open_live(DEFAULT_INTERFACE, BUFSIZ, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf); 
        return 1;
    }

    int link_type = pcap_datalink(pcap_handle);
    switch (link_type) {
        case DLT_EN10MB:    g_link_header_size = 14; break;
        case DLT_NULL:      g_link_header_size = 4;  break;
        case DLT_LINUX_SLL: g_link_header_size = 16; break;
        default:
            fprintf(stderr, "Unsupported link-layer type: %s\n", pcap_datalink_val_to_name(link_type)); 
            return 1;
    }

    log_event("Monitoring started. Press Ctrl+C to stop.");
    
    pcap_loop(pcap_handle, -1, packet_handler, NULL);
    
    log_event("Port Scan Detector shutting down.");
    pcap_close(pcap_handle);
    
    return 0;
}