#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <mosquitto.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>

// ================== CONFIGURATION ==================
#define MAX_TRACKED_IPS 1024
#define ALERT_COOLDOWN 60
#define IP_IDLE_TIMEOUT 300
#define STATE_CLEANUP_INTERVAL 5
#define DEFAULT_INTERFACE "eth0" // Use "any" for local testing, "eth0" for deployment

// DoS / DDoS Config
#define DOS_PACKET_THRESHOLD 20
#define DOS_TIME_WINDOW 5
#define DDoS_UNIQUE_SOURCES_THRESHOLD 10
#define DDoS_TIME_WINDOW 10

// Port Scan Config
#define PORT_SCAN_THRESHOLD 15
#define PORT_SCAN_TIME_WINDOW 10

// MQTT Config
#define MQTT_HOST "localhost"
#define MQTT_PORT 1883
#define MQTT_TOPIC "myids/alerts"

// ================== DATA STRUCTURES ==================
typedef struct { char ip[INET_ADDRSTRLEN]; int count; time_t window_start_time; time_t last_seen; int alerted; } DoSTracker;
typedef struct { char ip[INET_ADDRSTRLEN]; time_t timestamp; } AttackerInfo;
typedef struct { char dest_ip[INET_ADDRSTRLEN]; AttackerInfo attackers[MAX_TRACKED_IPS]; int attacker_count; time_t last_alert_time; time_t last_seen; } DDoSTracker;
typedef struct { char src_ip[INET_ADDRSTRLEN]; char dst_ip[INET_ADDRSTRLEN]; uint16_t ports[MAX_TRACKED_IPS]; int port_count; time_t window_start_time; time_t last_alert_time; time_t last_seen; } PortScanTracker;

// ================== GLOBAL VARIABLES ==================
pcap_t *pcap_handle = NULL;
struct mosquitto *mosq = NULL;
volatile sig_atomic_t running = 1;
int g_link_header_size = 0;

DoSTracker dos_list[MAX_TRACKED_IPS]; int dos_list_size = 0;
DDoSTracker ddos_list[MAX_TRACKED_IPS]; int ddos_list_size = 0;
PortScanTracker port_scan_list[MAX_TRACKED_IPS]; int port_scan_list_size = 0;

// ================== FUNCTION DECLARATIONS ==================
void log_event(const char *message);
void cleanup_state();
void process_tls_handshake(const u_char *payload, int len);
void process_dos(const char *src_ip);
void process_ddos(const char *src_ip, const char *dst_ip);
void process_port_scan(const char *src_ip, const char *dst_ip, uint16_t dst_port, const struct tcphdr *tcp);
void process_ip(const u_char *packet);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void shutdown_handler(int signum);

// ================== IMPLEMENTATION ==================

void log_event(const char *message) {
    FILE *log = fopen("logs/ids.log", "a");
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

void log_portscan(const char *message) {
    FILE *log = fopen("logs/port_scan.log", "a");
    if (log) {
        time_t now = time(NULL);
        char time_str[26];
        ctime_r(&now, time_str);
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log, "[%s] %s\n", time_str, message);
        fclose(log);
    }
}

void cleanup_state() {
    time_t now = time(NULL);
    int i = 0;
    while (i < ddos_list_size) { if (now - ddos_list[i].last_seen > IP_IDLE_TIMEOUT) { ddos_list[i] = ddos_list[ddos_list_size - 1]; ddos_list_size--; } else { i++; } }
    i = 0;
    while (i < dos_list_size) { if (now - dos_list[i].last_seen > IP_IDLE_TIMEOUT) { dos_list[i] = dos_list[dos_list_size - 1]; dos_list_size--; } else { i++; } }
    i = 0;
    while (i < port_scan_list_size) { if (now - port_scan_list[i].last_seen > IP_IDLE_TIMEOUT) { port_scan_list[i] = port_scan_list[port_scan_list_size - 1]; port_scan_list_size--; } else { i++; } }
}

void process_tls_handshake(const u_char *payload, int len) {
    if (len < 44) return;
    if (payload[0] != 0x16 || payload[5] != 0x02) return;
    uint8_t session_id_length = payload[43];
    int cipher_suite_offset = 43 + 1 + session_id_length;
    if (len < cipher_suite_offset + 2) return;
    uint16_t cipher_suite_id = (payload[cipher_suite_offset] << 8) + payload[cipher_suite_offset + 1];
    if (cipher_suite_id == 0x002f || cipher_suite_id == 0x0035) {
        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg), "ALERT: Weak TLS Cipher Suite detected (ID: 0x%04x). System may be vulnerable to signature forgery (Birthday Attack).", cipher_suite_id);
        log_event(alert_msg);
        if (mosq) mosquitto_publish(mosq, NULL, MQTT_TOPIC, strlen(alert_msg), alert_msg, 1, false);
    }
}

void process_dos(const char *src_ip) {
    time_t now = time(NULL);
    int found_ip = -1;
    for (int i = 0; i < dos_list_size; i++) {
        if (strcmp(dos_list[i].ip, src_ip) == 0) { found_ip = i; break; }
    }
    if (found_ip == -1) {
        if (dos_list_size >= MAX_TRACKED_IPS) return;
        found_ip = dos_list_size++;
        snprintf(dos_list[found_ip].ip, INET_ADDRSTRLEN, "%s", src_ip);
        dos_list[found_ip].count = 0;
        dos_list[found_ip].alerted = 0;
        dos_list[found_ip].window_start_time = now;
    }
    DoSTracker *target = &dos_list[found_ip];
    target->last_seen = now;
    if (now - target->window_start_time > DOS_TIME_WINDOW) {
        target->window_start_time = now;
        target->count = 1;
        target->alerted = 0;
    } else {
        target->count++;
    }
    if (target->count >= DOS_PACKET_THRESHOLD && !target->alerted) {
        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg), "ALERT: Potential DoS from %s (%d packets in %d seconds)", target->ip, target->count, DOS_TIME_WINDOW);
        log_event(alert_msg);
        if (mosq) mosquitto_publish(mosq, NULL, MQTT_TOPIC, strlen(alert_msg), alert_msg, 1, false);
        target->alerted = 1;
    }
}

void process_ddos(const char *src_ip, const char *dst_ip) {
    time_t now = time(NULL);
    int found_dest = -1;
    for (int i = 0; i < ddos_list_size; i++) {
        if (strcmp(ddos_list[i].dest_ip, dst_ip) == 0) { found_dest = i; break; }
    }
    if (found_dest == -1) {
        if (ddos_list_size >= MAX_TRACKED_IPS) return;
        found_dest = ddos_list_size++;
        snprintf(ddos_list[found_dest].dest_ip, INET_ADDRSTRLEN, "%s", dst_ip);
        ddos_list[found_dest].attacker_count = 0;
        ddos_list[found_dest].last_alert_time = 0;
    }
    DDoSTracker *target = &ddos_list[found_dest];
    target->last_seen = now;
    int i = 0;
    while (i < target->attacker_count) {
        if (now - target->attackers[i].timestamp > DDoS_TIME_WINDOW) {
            target->attackers[i] = target->attackers[target->attacker_count - 1];
            target->attacker_count--;
        } else { i++; }
    }
    int found_attacker = 0;
    for (i = 0; i < target->attacker_count; i++) {
        if (strcmp(target->attackers[i].ip, src_ip) == 0) { found_attacker = 1; break; }
    }
    if (!found_attacker && target->attacker_count < MAX_TRACKED_IPS) {
        snprintf(target->attackers[target->attacker_count].ip, INET_ADDRSTRLEN, "%s", src_ip);
        target->attackers[target->attacker_count].timestamp = now;
        target->attacker_count++;
    }
    if (target->attacker_count >= DDoS_UNIQUE_SOURCES_THRESHOLD && (now - target->last_alert_time > ALERT_COOLDOWN)) {
        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg), "ALERT: Possible DDoS on %s from %d unique sources (in last %d sec)", target->dest_ip, target->attacker_count, DDoS_TIME_WINDOW);
        log_event(alert_msg);
        if (mosq) mosquitto_publish(mosq, NULL, MQTT_TOPIC, strlen(alert_msg), alert_msg, 1, false);
        target->last_alert_time = now;
    }
}

void process_port_scan(const char *src_ip, const char *dst_ip, uint16_t dst_port, const struct tcphdr *tcp) {
    if (!(tcp->syn && !tcp->ack)) return;
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
        if (target->ports[i] == dst_port) { port_already_scanned = true; break; }
    }
    if (!port_already_scanned && target->port_count < MAX_TRACKED_IPS) {
        target->ports[target->port_count++] = dst_port;
    }
    if (target->port_count >= PORT_SCAN_THRESHOLD && (now - target->last_alert_time > ALERT_COOLDOWN)) {
        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg), "ALERT: Port Scan detected! %s is scanning %s. %d unique ports in %d seconds.", target->src_ip, target->dst_ip, target->port_count, PORT_SCAN_TIME_WINDOW);
        log_event(alert_msg);
        log_portscan(alert_msg);
        if (mosq) mosquitto_publish(mosq, NULL, MQTT_TOPIC, strlen(alert_msg), alert_msg, 1, false);
        target->last_alert_time = now;
    }
}

void process_ip(const u_char *packet) {
    const struct iphdr *ip = (const struct iphdr *)(packet + g_link_header_size);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));

    process_dos(src_ip);
    process_ddos(src_ip, dst_ip);

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + g_link_header_size + (ip->ihl * 4));
        uint16_t dst_port = ntohs(tcp->dest);
        
        process_port_scan(src_ip, dst_ip, dst_port, tcp);

        if (ntohs(tcp->dest) == 443 || ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 4433 || ntohs(tcp->source) == 4433) {
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

    if (g_link_header_size == 14) {
        const struct ether_header *eth = (const struct ether_header *)packet;
        uint16_t ether_type = ntohs(eth->ether_type);
        // Since MITM/ARP is removed, we only process IP packets.
        if (ether_type == ETHERTYPE_IP) {
            process_ip(packet);
        }
    } else {
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
    
    FILE *log = fopen("logs/ids.log", "w"); if (log) fclose(log);

    log_event("MyIDS starting...");
    signal(SIGINT, shutdown_handler);

    pcap_handle = pcap_open_live(DEFAULT_INTERFACE, BUFSIZ, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf); return 1;
    }

    int link_type = pcap_datalink(pcap_handle);
    switch (link_type) {
        case DLT_EN10MB:    g_link_header_size = 14; break;
        case DLT_NULL:      g_link_header_size = 4;  break;
        case DLT_LINUX_SLL: g_link_header_size = 16; break;
        default:
            fprintf(stderr, "Unsupported link-layer type: %s\n", pcap_datalink_val_to_name(link_type)); return 1;
    }

    // A BPF filter is not strictly necessary but can improve performance.
    // We will capture all IP traffic.
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "pcap error: %s\n", pcap_geterr(pcap_handle)); return 1;
    }

    mosquitto_lib_init();
    mosq = mosquitto_new("myids_client", true, NULL);
    if (mosq) {
        mosquitto_loop_start(mosq);
        if (mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60) == MOSQ_ERR_SUCCESS) log_event("Connected to MQTT broker.");
        else log_event("ERROR: Unable to connect to MQTT broker.");
    }

    log_event("Monitoring started. Press Ctrl+C to stop.");
    
    pcap_loop(pcap_handle, -1, packet_handler, NULL);

    log_event("MyIDS shutting down.");
    cleanup_state();
    pcap_close(pcap_handle);
    if (mosq) {
        mosquitto_disconnect(mosq);
        mosquitto_loop_stop(mosq, true);
        mosquitto_destroy(mosq);
    }
    mosquitto_lib_cleanup();

    return 0;
}
