# 📡 Network Intrusion Detection System (NIDS)

A lightweight, real-time **Network Intrusion Detection System** built in C using **libpcap** and **MQTT**, capable of detecting:

- 🚨 **DoS (Denial of Service) attacks**
- 🌐 **DDoS attacks based on distributed packet sources**
- 🔎 **Port Scanning attempts**
- 🔐 **Weak TLS Cipher Suite detection (0x002f, 0x0035)**
- 📥 Real-time alerts published through **MQTT broker**

This system captures packets from a live network interface, analyzes TCP/IP headers in real time, and logs & publishes alerts to subscribed monitoring systems.

---

## ✨ Features
| Feature | Description |
|---------|------------|
| Packet Sniffing | Uses `libpcap` to capture live packets |
| DoS detection | Detects sources sending excessive packets |
| DDoS detection | Detects multiple sources attacking same destination |
| Port scan detection | Detects SYN-based port scanning |
| TLS vulnerability scan | Detects weak cipher-suite use in ClientHello |
| MQTT Integration | Publishes alerts to MQTT topic `myids/alerts` |
| Logging | Logs events to `ids.log` |

---

## 🧰 Technologies Used
- **C (GCC)**
- **libpcap**
- **Mosquitto / Eclipse Paho MQTT**
- **Linux / Debian**
  
---

## 🛠 Installation

### 1️⃣ Install Dependencies
```bash
sudo apt update
sudo apt install libpcap-dev
sudo apt install mosquitto mosquitto-clients libmosquitto-dev
```

### 2️⃣ Clone Repository
```bash
git clone https://github.com/yourusername/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

### 3️⃣ Build the Program
```bash
make
```

### 4️⃣ Run the IDS
```bash
sudo ./myids
```

## 🔧 Configuration
```txt
interface=eth0
mqtt_host=localhost
```

## 📤 MQTT Alerts Example Messages
```txt
ALERT: Potential DoS from 185.125.190.83 (20 packets in 5 seconds)
ALERT: Port Scan detected! 127.0.0.1 is scanning 127.0.0.1. 15 unique ports in 10 seconds.
ALERT: Weak TLS Cipher Suite detected (ID: 0x002f)
```

Subscribe to MQTT topic:
```bash
mosquitto_sub -t "myids/alerts"
```

### 🧪 Test TLS Detector Example
```bash
sudo ./test_tls
```

### 🧱 Key Functions Overview
#### Packet Capture
```c
pcap_loop(pcap_handle, -1, packet_handler, NULL);
```

#### Packet Handler
```c
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
```

#### DoS Detection
```c
void process_dos(const char *src_ip);
```

#### Port Scan Detection
```c
void process_port_scan(const char *src_ip, const char *dst_ip, uint16_t dst_port, const struct tcphdr *tcp);
```

#### TLS Weak Cipher Detection
```c
void process_tls_handshake(const u_char *payload, int len);
```

#### Logging
```c
void log_event(const char *message);
```

#### MQTT Publish
```c
mosquitto_publish(mosq, NULL, MQTT_TOPIC, strlen(alert_msg), alert_msg, 1, false);
```

## ⚠️ Security Notes
- **Do NOT upload .pem keys publicly**
- **Logs may contain sensitive info**
- **Must run with root privileges**  
---


## 📄 License
Distributed under MIT License
---

## 🤝 Contributing
Contributions welcome!
Open an issue or submit PR. 
---

## ⭐ Support
If you like this project, consider giving it a Star ⭐ on GitHub! 
---


