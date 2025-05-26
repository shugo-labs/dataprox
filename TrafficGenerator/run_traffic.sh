#!/bin/bash

interface=$1
moat_private_ip=$2
private_ip=$3
node_index=$4
total_duration=$5

# Step 0: Install required Python packages
pip3 install --quiet faker scapy pycryptodome

# Step 1: Run GRE setup
python3 gre_setup.py tgen $moat_private_ip $private_ip $interface $node_index

# Step 2: Generate playlist
python3 -c "
import json
from generate_playlist import create_random_playlist

playlist = create_random_playlist(total_seconds=$total_duration)
with open('/tmp/playlist.json', 'w') as f:
    json.dump(playlist, f)
"

# Step 3: Run traffic generator with playlist
nohup python3 traffic_generator_training.py \
  --playlist /tmp/playlist.json \
  --receiver-ips 10.0.0.1 \
  --interface ipip-tgen-$node_index \
  > /tmp/traffic_generator.log 2>&1 &