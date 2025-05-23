#!/bin/bash

# Update and install necessary packages
apt update && apt upgrade -y
apt install -y tcpdump tshark sysstat ifstat dstat vnstat snmpd python3-pip
apt install -y npm && npm install -g pm2

# Install Python packages
pip3 install scapy pandas numpy psutil websockets asyncio pymongo python-dotenv

# Create directories for logs and data
mkdir -p traffic_flood_detection/logs
mkdir -p traffic_flood_detection/data

# Start necessary services
systemctl enable --now sysstat
systemctl enable --now snmpd

pm2 kill && pm2 flush

# Start the data capture script in the background
pm2 start "python3 collect_features.py" --name collect_features