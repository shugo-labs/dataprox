#!/bin/bash

interface=$1
moat_private_ip=$2
private_ip=$3
node_index=$4
total_duration=$5

# Step 0: Install required Python packages
pip3 install --quiet faker scapy pycryptodome

# Step 1: Run GRE setup
cd ~/dataprox && python3 gre_setup.py tgen $moat_private_ip $private_ip $interface $node_index

# Step 2: Generate and execute playlist
cd ~/dataprox/TrafficGenerator && python3 - <<EOF
import json
import subprocess
import time
import signal
import os
import random
from typing import Dict

def get_attack_classes() -> Dict[str, list]:
    """Get all available attack classes.
    
    Returns:
        Dictionary mapping internal labels with the traffic vectors.
    """
    return {
        "BENIGN": ['udp_traffic', 'tcp_traffic'],

        "TCP_SYN_FLOOD": [
            'tcp_variable_window_syn_flood',
            'tcp_amplified_syn_flood_reflection',
            'tcp_async_slow_syn_flood',
            'tcp_batch_syn_flood',
            'tcp_randomized_syn_flood',
            'tcp_variable_ttl_syn_flood',
            'tcp_targeted_syn_flood_common_ports',
            'tcp_adaptive_flood',
            'tcp_batch_flood',
            'tcp_variable_syn_flood',
            'tcp_max_randomized_flood'
        ],

        "UDP_FLOOD": [
            'udp_malformed_packet',
            'udp_multi_protocol_amplification_attack',
            'udp_adaptive_payload_flood',
            'udp_compressed_encrypted_flood',
            'udp_max_randomized_flood',
            'udp_and_tcp_flood',
            'udp_single_ip_flood',
            'udp_ip_packet',
            'udp_reflection_attack',
            'udp_memcached_amplification_attack',
            'udp_hybrid_flood',
            'udp_dynamic_payload_flood',
            'udp_encrypted_payload_flood'
        ]
    }

def create_random_playlist(total_seconds, role=None, seed=None):
    """
    Create a random playlist totaling a specified duration, either for an 'attacker' or 'benign' role.
    Generates a playlist consisting of random activities ('pause' or a class type) with durations summing up to the specified total duration.

    Args:
        total_seconds (int): The total duration of the playlist in seconds.
        role (str, optional): The role for the playlist ('attacker' or 'benign'). Defaults to None.
        seed (int, optional): The seed for the random number generator. If None, the seed is not set.

    Returns:
        list: A list of dictionaries, each containing 'name', 'class_vector', 'label_identifier', and 'duration'.
    """
    if seed is not None:
        random.seed(seed)

    type_class_map = get_attack_classes()
    playlist = []
    current_total = 0
    attack_labels = [key for key in type_class_map.keys() if key != "BENIGN"]
    benign_labels = ["BENIGN"]

    # Role-specific weight calculation using a dictionary
    weights = {
        "aggressive": (0.8, 0.2),
        "soft": (0.2, 0.8)
    }.get(role, (0.5, 0.5))  # Default to (0.5, 0.5) if machine is hybrid

    attack_weight, benign_weight = weights

    # Calculate individual weights
    attack_weight_per_label = attack_weight / len(attack_labels)
    combined_labels = attack_labels + benign_labels
    weights = [attack_weight_per_label] * len(attack_labels) + [benign_weight]

    while current_total < total_seconds:
        # Select label based on role-specific weight distribution
        name = random.choices(combined_labels, weights, k=1)[0]
        # Determine the duration for this step (ensuring we don't exceed total_seconds)
        duration = min(random.randint(60, 180), total_seconds - current_total)

        # If role is "Benign" and label "BENIGN" is chosen, output a grouped unit with two class_vectors.
        if role == "soft" and name == "BENIGN":
            benign_unit = {
                "name": "BENIGN",
                "classes": [
                    {
                        "class_vector": "tcp_traffic",
                        "duration": duration
                    },
                    {
                        "class_vector": "udp_traffic",
                        "duration": duration
                    }
                ]
            }
            playlist.append(benign_unit)
        else:
            # For all other cases, use the existing logic
            class_vector = random.choice(type_class_map[name]) if name != "pause" else None

            # Add activity to the playlist
            playlist.append({
                "name": name, 
                "class_vector": class_vector,
                "duration": duration
            })

        current_total += duration

    return playlist

# Generate playlist
playlist = create_random_playlist(total_seconds=$total_duration)

# Process each entry in the playlist
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