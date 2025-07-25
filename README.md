
# SOC PCAP Analyzer

A lightweight Python tool designed to help detect common network-based security events from packet capture (PCAP) files.

This tool is intended for junior SOC analysts and security learners. It supports `.pcap` and `.pcapng` formats and performs basic detections such as brute force login attempts, port scans, and large data exfiltration.

---

## Features

### Brute Force Detection
Detects repeated connection attempts from the same IP within a short time window.
This is useful for identifying potential brute force attacks on services like SSH,RDP or FTP.

### Port Scan Detection (vertical, horizontal)
Flags IPs that attempt connections on multiple ports in a short timeframe.

### Large Data Transfer Detection
Identifies hosts sending large amounts of data, potentially indicating data exfiltration.

### Output as JSON Report
Structured output that summarizes suspicious activity.

---

## How to Use

```bash
python3 pcap_analyzer.py \
  --file ./samples/example.pcapng \
  --output ./report.json \
  --brute-threshold 10 \
  --scan-threshold 15 \
  --scan-window 60 \
````

---

## Arguments

| Flag                   | Description                                                      |
| ---------------------- | ---------------------------------------------------------------- |
| `--file`               | Path to the PCAP file                                            |
| `--output`             | Path to write the detection report (JSON)                        |
| `--brute-threshold`    | Number of attempts from same IP to trigger brute force detection |
| `--window`             | ime window in seconds for brute-force detection                  |
| `--scan-threshold`     | Number of ports to scan within a short window to trigger         |
| `--scan-window`        | Time window in minutes for port scan detection                   |
| `--file-threshold`     | Transfer size in MB to trigger data exfiltration alert           |
| `--whitelisted_ips`    | List of IPs to ignore for data exfiltration detection            |


---

## Output Format

Output is saved as a structured JSON report:

```json
{
  "brute_force": [
     {
            "ip": "192.168.11.105",
            "total_attempts": 433,
            "total_duration_seconds": 37.69,
            "avg_time_between_attempts": 0.09,
            "min_time_between_attempts": 0.0,
            "max_time_between_attempts": 3.64,
            "suspicious_windows": 424,
            "first_attempt": "2025-07-22T06:31:04.151818",
            "last_attempt": "2025-07-22T06:31:41.841331",
            "attack_types": [
                "ssh"
            ],
            "target_ports": [
                22
            ],
            "message": "Potential brute force attack detected",
            "severity": "HIGH"
        }
  ],
  "port_scans": [
    {
            "ip": "192.168.11.105",
            "horizontal_ports": [],
            "vertical_ports": [
                20, 21, 22, 23, 24, 25, 26, 27, 28
            ],
            "message": "Potential port scanning detected",
            "severity": "MEDIUM",
            "type": [
                "vertical"
            ],
            "first_seen": "2025-07-25T06:20:46.682306",
            "last_seen": "2025-07-25T06:20:46.683016"
        }
  ],
  "large_transfers": [
   {
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "total_size": 1100000,
    "packet_count": 2,
    "message": "Potential data exfiltration: 1.05 MB sent from 192.168.1.10 to 8.8.8.8",
    "severity": "MEDIUM"
    }
  ]
}
```

---

## Sample Use Cases

-  Detect SSH brute-force attacks in internal traffic
- Identify possible port scanning or reconnaissance behavior
- Flag potential data exfiltration from compromised hosts

---

## PCAPs Tested

-  Sample captures generated with Kali Linux tools (Hydra, Nmap)
-  Public PCAPs from online security datasets
-  Custom simulated PCAPs

---

## Motivation

This project was built to simulate the type of network traffic analysis done in real-world SOC environments. It helped me gain hands-on experience with packet inspection, detection logic, and building CLI tools for cybersecurity tasks.

🛡️ Cybersecurity Enthusiast | 💻 Software Engineer

---

```


