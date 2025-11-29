# Embedded-NIDS-RaspberryPi
Real-time Network Intrusion Detection System (NIDS) for embedded ARM platforms using libpcap and MQTT


# Smart Embedded Network Intrusion Detection System (NIDS)

Platform: Raspberry Pi 3B (ARM Cortex-A53) / Debian (WSL)
Language: C (Low-level networking)
Libraries: libpcap, libmosquitto, pthread

Project Overview

This project implements a lightweight, real-time Network Intrusion Detection System designed for resource-constrained embedded devices. Unlike heavy enterprise solutions (Snort/Suricata), this custom engine operates at the packet level to detect specific attack signatures with minimal CPU overhead.

Key Features

Packet Sniffing: Uses raw sockets via libpcap to capture TCP/IP traffic in real-time.

Attack Detection Modules:

DoS/DDoS: Tracks SYN packet rates per source IP using stateful counters.

Port Scanning: Identifies rapid connection attempts across multiple ports.

Weak Encryption: Parses TLS Handshake headers to detect deprecated cipher suites (e.g., SHA-1).

Real-Time Alerting: Publishes threat data to an admin dashboard via MQTT protocol.

Technical Implementation

Memory Management: Optimized for limited RAM (1GB) using efficient data structures.

Concurrency: Multi-threaded packet processing to prevent packet loss during high traffic.

Cross-Platform: Developed on WSL (Debian) and deployed on Raspberry Pi OS.



Build & Run
