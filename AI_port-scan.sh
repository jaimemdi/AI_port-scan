#!/bin/bash

# Colors for pretty output
GREEN="\e[32m"
CYAN="\e[36m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Pretty print functions
print_info() {
  echo -e "${CYAN}[*] $1${RESET}"
}
print_success() {
  echo -e "${GREEN}[+] $1${RESET}"
}
print_warning() {
  echo -e "${YELLOW}[!] $1${RESET}"
}
print_error() {
  echo -e "${RED}[-] $1${RESET}"
}

# Function to extract open ports from a .gnmap file
extract_ports() {
  grep -oP '\d+/open' "$1" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'
}

# Check for IP argument
if [ -z "$1" ]; then
  print_error "Usage: $0 <IP>"
  exit 1
fi

TARGET_IP="$1"
REPORT_DIR="report_$TARGET_IP"
API_KEY="your api key"

# Create working directory
mkdir -p "$REPORT_DIR"
cd "$REPORT_DIR" || exit

print_info "Scan started for IP: $TARGET_IP"

# ---------- FAST TCP SCAN ----------
print_info "Running fast TCP scan..."
sudo nmap -sS -p- --open --min-rate 5000 -n "$TARGET_IP" -Pn -oG allPorts_tcp > /dev/null &
TCP_PID=$!

# ---------- PARALLEL UDP SCAN ----------
print_info "Running top 500 UDP ports scan..."
sudo nmap -sU --top-ports 500 -T5 --open "$TARGET_IP" -n -Pn -oG allPorts_udp > /dev/null &
UDP_PID=$!

# Wait for TCP scan to finish
wait $TCP_PID
print_success "TCP scan completed."

# Extract open TCP ports
TCP_PORTS=$(extract_ports allPorts_tcp)
print_info "Open TCP ports: $TCP_PORTS"

# Full TCP scan with service and version detection
print_info "Running detailed TCP scan..."
sudo nmap -sCV -p"$TCP_PORTS" "$TARGET_IP" -Pn -oN nmap_tcp.txt > /dev/null
print_success "Detailed TCP scan saved to nmap_tcp.txt"

# Wait for UDP scan
wait $UDP_PID
print_success "UDP scan completed."

# Extract open UDP ports
UDP_PORTS=$(extract_ports allPorts_udp)
print_info "Open UDP ports: $UDP_PORTS"

# Full UDP scan if ports were found
if [ -n "$UDP_PORTS" ]; then
  print_info "Running detailed UDP scan..."
  sudo nmap -sU -p"$UDP_PORTS" "$TARGET_IP" -Pn -oN nmap_udp.txt > /dev/null
  print_success "Detailed UDP scan saved to nmap_udp.txt"
else
  print_warning "No open UDP ports detected. Skipping detailed UDP scan."
  echo "No open UDP ports detected." > nmap_udp.txt
fi

# ---------- SEND TO DEEPSEEK AI ----------
print_info "Generating AI report via Deepseek..."

TCP_CONTENT=$(jq -Rs . < nmap_tcp.txt)
UDP_CONTENT=$(jq -Rs . < nmap_udp.txt)

PAYLOAD=$(jq -n \
  --arg tcp "$TCP_CONTENT" \
  --arg udp "$UDP_CONTENT" \
  '{
    model: "deepseek-coder",
    messages: [
      {
        role: "system",
        content: "You are a cybersecurity expert. Analyze the scan results and suggest potential attack vectors or notable findings."
      },
      {
        role: "user",
        content: "TCP scan results: \($tcp)\n\nUDP scan results: \($udp)"
      }
    ]
  }')

RESPONSE=$(curl -s https://api.deepseek.com/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

if echo "$RESPONSE" | jq -e . >/dev/null 2>&1; then
  echo "$RESPONSE" | jq -r '.choices[0].message.content' > ai_report.txt
  print_success "AI report generated and saved to ai_report.txt"
else
  print_error "Invalid response from the API. Saving raw output to ai_report_raw.txt"
  echo "$RESPONSE" > ai_report_raw.txt
fi
# ---------- CLEANUP ----------
print_info "Cleaning up temporary files..."
rm -f allPorts_tcp allPorts_udp
print_success "Temporary files removed."

# ---------- FINAL OUTPUT ----------
echo -e "\n${GREEN}===== FINAL SUMMARY =====${RESET}"
print_success "Open TCP ports: $TCP_PORTS"
print_success "Open UDP ports: $UDP_PORTS"
print_success "Reports saved to: $REPORT_DIR"
print_success "Scan completed successfully!"
