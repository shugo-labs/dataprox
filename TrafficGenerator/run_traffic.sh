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

# Step 3: Read and loop over each item in playlist.json, one at a time
python3 - <<EOF
import json
import subprocess
import time
import signal
import os

with open('/tmp/playlist.json') as f:
    playlist = json.load(f)

for entry in playlist:
    class_vector = entry['class_vector']
    duration = entry['duration']

    print(f"Starting traffic generation: class_vector={class_vector}, duration={duration}s")

    # Start the traffic generator process
    proc = subprocess.Popen(
        ["python3", "traffic_generator_training.py", class_vector,
        "--duration", str(duration),
        "--receiver-ips", "10.0.0.1",
        "--interface", f"ipip-tgen-${node_index}"],
        # preexec_fn=os.setsid  # <- this makes it a process group leader
    )

    # Sleep for the duration of this traffic pattern
    time.sleep(duration)

    # Kill the process if still running
    if proc.poll() is None:
        print(f"Terminating traffic generator: class_vector={class_vector}")
        proc.terminate()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
            subprocess.run(["pkill", "-9", "-f", "traffic_generator_training.py"])
            time.sleep(2)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            print("Forcefully killed the traffic generator group.")

    # Remove lingering traffic shaping lock
    lock_file = "/tmp/traffic_shaping.lock"
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            print("Lock file removed.")
        except Exception as e:
            print(f"Failed to remove lock file: {e}")


print("All traffic patterns completed.")
EOF