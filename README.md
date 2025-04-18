# AutoScanner - Network Port Scanning & AI Reporting

AutoScanner is an automated network scanning tool written in Bash that performs TCP and UDP port scans on a given IP address, generates detailed Nmap scan reports, and sends the results to the Deepseek AI API to analyze the potential attack vectors and vulnerabilities. It then stores the findings in a report directory.

## Features

- **TCP and UDP Scanning**: Performs both fast TCP port scanning and detailed UDP scanning of the top 500 ports.
- **AI-based Analysis**: Integrates with the Deepseek AI API to generate a security report based on the scan results.
- **Real-time Reporting**: Displays real-time output on open ports and completed scans.
- **Cleanup**: Deletes temporary scanning files after the process is completed.

## Requirements

- **Kali Linux** or any Linux distribution with the necessary tools installed.
- **Nmap**: For port scanning. If not installed, you can install it using:
- **jq**: A lightweight and flexible command-line JSON processor.
- **curl**: For making API requests to Deepseek. 

```bash
sudo apt install nmap
sudo apt install jq
sudo apt install curl
```


## Usage and Setup

```bash
git clone https://github.com/jaimemdi/AI_port-scan.git
cd AI_port-scan
sudo ./AI_port-scan.sh
```

