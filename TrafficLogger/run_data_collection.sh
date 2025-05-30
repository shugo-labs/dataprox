#!/bin/bash

# Update and install necessary packages
apt update && apt upgrade -y
apt install -y tcpdump tshark sysstat ifstat dstat vnstat snmpd python3-pip
apt install -y npm && npm install -g pm2

# Install Python packages
pip3 install scapy pandas numpy psutil websockets asyncio pymongo python-dotenv

# Start necessary services
systemctl enable --now sysstat
systemctl enable --now snmpd

# Export NODE_INDEX from environment variable or use default
export NODE_INDEX=${NODE_INDEX:-0}

# Start the data capture script in the background
pm2 start "python3 collect_features.py" --name collect_features --env NODE_INDEX=$NODE_INDEX