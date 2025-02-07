# Suricata-Project

![suricata](https://github.com/user-attachments/assets/8398860d-746b-48a7-b3e2-0c2a66447b7b)
![suricata2](https://github.com/user-attachments/assets/542c4ebc-7d50-44a4-970d-a3bb54847cba)


# Network Intrusion Detection with Suricata

## Project Overview
In this project, I deployed Suricata, an open-source intrusion detection system (IDS), to monitor network traffic for malicious activity. The objective was to identify and log potential threats in real-time using custom rules and alerting mechanisms.

## Objectives
- Set up Suricata on a Linux-based environment
- Capture and analyze network traffic
- Create custom rules to detect specific threats
- Generate alerts upon detecting malicious activity
- Log and review suspicious traffic for further analysis

## Setup

### Prerequisites
- Ubuntu 22.04 (or any Debian-based Linux distribution)
- Suricata installed (`apt install suricata`)
- A test network with simulated traffic
- Access to a log monitoring tool (e.g., Kibana or Splunk) for analysis

### Installing Suricata
```bash
sudo apt update && sudo apt install -y suricata
```

### Configuring Suricata
Modify the Suricata configuration file to enable logging and monitoring.

```bash
sudo nano /etc/suricata/suricata.yaml
```
Ensure the following lines are configured properly:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: json
      filename: /var/log/suricata/eve.json
```
Restart Suricata to apply changes:
```bash
sudo systemctl restart suricata
```

## Implementation

### Capturing Live Network Traffic
Suricata operates in IDS mode by default. To monitor live traffic, use:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```
(`eth0` should be replaced with your actual network interface.)

### Creating Custom Detection Rules
To detect SSH brute force attempts, add a custom rule in `/etc/suricata/rules/custom.rules`:
```shell
alert tcp any any -> any 22 (msg:"Potential SSH Brute Force"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)
```
This rule triggers an alert if more than five connection attempts are made to port 22 within 60 seconds.

Enable the rule in Suricata's configuration:
```bash
echo "include /etc/suricata/rules/custom.rules" | sudo tee -a /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

### Testing the Rule
Simulate an SSH brute force attack using Hydra:
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```
Check the Suricata logs for alerts:
```bash
sudo cat /var/log/suricata/fast.log
```
Expected output:
```
02/07/2025-15:45:12.123456 [**] [1:1000001:1] Potential SSH Brute Force [**] [Priority: 2] {TCP} 192.168.1.5:56789 -> 192.168.1.1:22
```

## Results & Conclusion
The project successfully identified SSH brute force attempts in real-time, generating alerts and logging suspicious activities. This implementation can be extended to detect other network threats such as malware, DDoS attempts, and unauthorized access attempts.

Future improvements include integrating Suricata with ELK (Elasticsearch, Logstash, and Kibana) for real-time data visualization and automating alert notifications with a SIEM solution.
