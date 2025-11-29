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

