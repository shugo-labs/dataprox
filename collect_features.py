import os
import time
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, UDP, TCP, GRE, Raw
from datetime import datetime
import threading
import psutil
from collections import Counter, defaultdict
import math
import resource
import socket
import json
import asyncio
import websockets
from pymongo import MongoClient
from dotenv import load_dotenv

class FloodDetector:

    AGG_INTERVAL = 10
    CONNECTIONS = set()  # Use a set to keep track of active WebSocket connections

    def __init__(self):

        # Load environment variables from .env file
        load_dotenv()

        # Retrieve individual parameters from the environment
        username = os.getenv("MONGODB_USERNAME")
        password = os.getenv("MONGODB_PASSWORD")
        host = os.getenv("MONGODB_HOST")
        database = os.getenv("MONGODB_DATABASE")
        collection = os.getenv("MONGODB_COLLECTION")

        # Initialize MongoDB connection
        #self.client = MongoClient(f"mongodb://{username}:{password}@{host}/admin?replicaSet=replicaset&tls=true")
        self.client = MongoClient("mongodb://127.0.0.1:27017/")

        self.db = self.client[database]
        self.collection = self.db[collection]

        self.last_features = {}  # Store the latest aggregated features
        self.local_ip = self.get_local_ip()  # Automatically get the local IP address
        self.protocol = ""
        
        # Packet Variables Initialization
        self.fwd_packet_count, self.bwd_packet_count = 0, 0
        self.fwd_packet_sizes, self.bwd_packet_sizes = [], []
        self.fwd_payload_sizes, self.bwd_payload_sizes = [], []
        self.fwd_header_sizes, self.bwd_header_sizes = [], []

        # GRE-specific variables
        self.gre_checksum_present = 0
        self.gre_routing_present = 0
        self.gre_key_present = 0
        self.gre_sequence_present = 0
        self.gre_strict_source_route = 0
        self.gre_recursion_control = 0
        self.gre_version_anomalies = 0
        self.gre_protocol_types = []
        self.gre_tunneled_protocols = []

        self.init_win_bytes = 0
        self.frag_flags, self.proto_anomalies = 0, 0
        self.flow_inter_arrival_times, self.fwd_inter_arrival_times, self.bwd_inter_arrival_times = [], [], []

        # TCP Variables for DDoS detection (for tunneled TCP)
        self.psh_flag_count_fwd, self.urg_flag_count_fwd = 0, 0
        self.fin_flag_count_fwd, self.syn_flag_count_fwd = 0, 0
        self.rst_flag_count_fwd, self.ack_flag_count_fwd = 0, 0
        self.cwe_flag_count_fwd, self.ece_flag_count_fwd = 0, 0
        self.psh_flag_count_bwd, self.urg_flag_count_bwd = 0, 0
        self.fin_flag_count_bwd, self.syn_flag_count_bwd = 0, 0
        self.rst_flag_count_bwd, self.ack_flag_count_bwd = 0, 0
        self.cwe_flag_count_bwd, self.ece_flag_count_bwd = 0, 0

        # Additional SYN Flood specific variables
        self.half_open_connections = 0
        self.handshake_completions = 0
        self.syn_packets = defaultdict(int)
        self.syn_ack_packets = defaultdict(int)

        # IP/Port Variables Initialization (for tunneled traffic)
        self.source_ips, self.source_ports, self.dest_ports = [], [], []
        self.udp_source_ports, self.udp_dest_ports = [], []
        self.tcp_source_ports, self.tcp_dest_ports = [], []
        self.gre_source_ips, self.gre_dest_ips = [], []

        # Flow Variables Initialization
        self.flow_durations, self.packets_per_flow, self.flow_bytes, self.flow_packets = {}, {}, {}, {}
        self.current_flows = 0

        # Labels Initialization
        self.labels = []

        # System Monitoring Variables Initialization
        self.cpu_util, self.mem_util, self.packet_drop = 0, 0, 0
        self.fd_util, self.io_wait, self.net_errors, self.load_avg = 0, 0, 0, 0

        self.last_packet_time, self.last_fwd_packet_time, self.last_bwd_packet_time = None, None, None  # Track last packet times


    def write_to_mongodb(self, features):
        try:
            # Ensure features is a dictionary
            if isinstance(features, dict):
                # Directly convert numpy integers to standard int
                for key, value in features.items():
                    if isinstance(value, np.integer):
                        features[key] = int(value)

                # Store the data row in MongoDB
                self.collection.insert_one(features)
                print(f"Write to MongoDB successful: {features}")
            else:
                raise TypeError("Features must be a dictionary")
        except Exception as e:
            self.log_error(f"Mongodb writing error: {e}")
            print(f"Mongodb writing error: {e}")

    def custom_json_encoder(self, obj):
        # If obj is a numpy integer, convert to a standard int
        if isinstance(obj, np.integer):
            return int(obj)
        # If obj is a string, return it as is (no conversion needed)
        elif isinstance(obj, str):
            return obj
        # Handle dictionaries and lists recursively
        elif isinstance(obj, dict):
            return {k: self.custom_json_encoder(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.custom_json_encoder(item) for item in obj]
        # Raise an error for unsupported types
        raise TypeError(f'Object of type {type(obj)} is not JSON serializable')
        
    def get_local_ip(self):
        """Retrieve the local IP address."""
        try:
            # Get the hostname of the local machine
            hostname = socket.gethostname()
            # Get the local IP address using the hostname
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return "0.0.0.0"  # Fallback IP if there's an error
        
    def monitor_system_metrics(self):
        while True:
            self.cpu_util = psutil.cpu_percent(interval=1)
            self.mem_util = psutil.virtual_memory().percent

            # Get file descriptor limits using resource module
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            
            # Count file descriptors manually from /proc/<pid>/fd
            pid = os.getpid()
            proc_fd = f'/proc/{pid}/fd'

            current_fds = len(os.listdir(proc_fd)) if os.path.exists(proc_fd) else 0
                
            self.fd_util = (current_fds / hard_limit) * 100 if hard_limit > 0 else 0

            self.io_wait = psutil.cpu_times_percent().iowait
            self.load_avg = os.getloadavg()[0]

            # Network statistics
            net_stats = psutil.net_io_counters()
            self.packet_drop = (net_stats.dropin + net_stats.dropout)

            time.sleep(self.AGG_INTERVAL - 1)  # Adjust sleep to account for the 1-second interval above

    def capture_packets(self):

        def process_packet(packet):
            try:
                if packet.haslayer(IP):

                    current_time = packet.time
                    header_size = len(packet[IP])
                    packet_size = len(packet)
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Add outer IP addresses for GRE tunnels
                    self.gre_source_ips.append(src_ip)
                    self.gre_dest_ips.append(dst_ip)

                    flow_id = None

                    # Handle GRE packets
                    if packet.haslayer(GRE):
                        self.protocol = "GRE"
                        header_size += len(packet[GRE])
                        
                        # Extract GRE header information
                        gre_layer = packet[GRE]
                        
                        # GRE flags analysis
                        if hasattr(gre_layer, 'chksum_present') and gre_layer.chksum_present:
                            self.gre_checksum_present += 1
                        if hasattr(gre_layer, 'routing_present') and gre_layer.routing_present:
                            self.gre_routing_present += 1
                        if hasattr(gre_layer, 'key_present') and gre_layer.key_present:
                            self.gre_key_present += 1
                        if hasattr(gre_layer, 'seqnum_present') and gre_layer.seqnum_present:
                            self.gre_sequence_present += 1
                        if hasattr(gre_layer, 'strict_route_source') and gre_layer.strict_route_source:
                            self.gre_strict_source_route += 1
                        if hasattr(gre_layer, 'recursion_control'):
                            self.gre_recursion_control += gre_layer.recursion_control
                        
                        # Check GRE version (should be 0 for standard GRE)
                        if hasattr(gre_layer, 'version') and gre_layer.version != 0:
                            self.gre_version_anomalies += 1
                        
                        # Track protocol types
                        if hasattr(gre_layer, 'proto'):
                            self.gre_protocol_types.append(gre_layer.proto)
                        
                        # Create flow ID for GRE tunnel
                        gre_key = getattr(gre_layer, 'key', 0) if hasattr(gre_layer, 'key') and gre_layer.key_present else 0
                        flow_id = (src_ip, dst_ip, gre_key, "GRE")
                        
                        # Analyze tunneled payload
                        if gre_layer.payload:
                            tunneled_packet = gre_layer.payload
                            
                            # If the tunneled packet is IP
                            if tunneled_packet.haslayer(IP):
                                inner_ip = tunneled_packet[IP]
                                self.source_ips.append(inner_ip.src)
                                
                                # Track tunneled protocol
                                if tunneled_packet.haslayer(TCP):
                                    self.gre_tunneled_protocols.append("TCP")
                                    self.tcp_source_ports.append(tunneled_packet[TCP].sport)
                                    self.tcp_dest_ports.append(tunneled_packet[TCP].dport)
                                    
                                    # Track TCP flags for tunneled traffic
                                    if inner_ip.src == self.local_ip:
                                        self.track_tcp_flags(tunneled_packet, direction='fwd')
                                    else:
                                        self.track_tcp_flags(tunneled_packet, direction='bwd', flow_id=flow_id)
                                        
                                elif tunneled_packet.haslayer(UDP):
                                    self.gre_tunneled_protocols.append("UDP")
                                    self.udp_source_ports.append(tunneled_packet[UDP].sport)
                                    self.udp_dest_ports.append(tunneled_packet[UDP].dport)
                                    
                                    if len(tunneled_packet[UDP].payload) == 0:
                                        self.proto_anomalies += 1
                                else:
                                    self.gre_tunneled_protocols.append("OTHER")

                    elif packet.haslayer(UDP):
                        self.protocol = "UDP"
                        header_size += len(packet[UDP])
                        self.udp_source_ports.append(packet[UDP].sport)
                        self.udp_dest_ports.append(packet[UDP].dport)
                        flow_id = (src_ip, packet[IP].dst, packet[UDP].sport, packet[UDP].dport)
                        self.source_ips.append(src_ip)

                        if len(packet[UDP].payload) == 0:
                            self.proto_anomalies += 1

                    elif packet.haslayer(TCP):
                        self.protocol = "TCP"
                        header_size += len(packet[TCP])
                        self.tcp_source_ports.append(packet[TCP].sport)
                        self.tcp_dest_ports.append(packet[TCP].dport)
                        flow_id = (src_ip, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                        self.source_ips.append(src_ip)

                        # Track initial window bytes
                        self.init_win_bytes += packet[TCP].window  

                    if flow_id:
                        # Update flow statistics
                        self.flow_bytes[flow_id] = self.flow_bytes.get(flow_id, 0) + packet_size
                        self.flow_packets[flow_id] = self.flow_packets.get(flow_id, 0) + 1

                    if src_ip == self.local_ip:
                        self.fwd_packet_count += 1
                        self.fwd_packet_sizes.append(packet_size)
                        self.fwd_header_sizes.append(header_size)

                        if packet.haslayer(UDP):
                            self.fwd_payload_sizes.append(len(packet[UDP].payload))
                        elif packet.haslayer(GRE):
                            # For GRE, calculate payload size as total packet minus headers
                            gre_payload_size = packet_size - header_size
                            self.fwd_payload_sizes.append(gre_payload_size)

                        if packet.haslayer(TCP) and not packet.haslayer(GRE):
                            # Track TCP Flags Forward (only for non-tunneled TCP)
                            self.track_tcp_flags(packet, direction='fwd')

                        if self.last_fwd_packet_time is not None:
                            self.fwd_inter_arrival_times.append(current_time - self.last_fwd_packet_time)

                        self.last_fwd_packet_time = current_time

                    else:
                        self.bwd_packet_count += 1
                        self.bwd_packet_sizes.append(packet_size)
                        self.bwd_header_sizes.append(header_size)

                        if packet.haslayer(UDP):
                            self.bwd_payload_sizes.append(len(packet[UDP].payload))
                        elif packet.haslayer(GRE):
                            # For GRE, calculate payload size as total packet minus headers
                            gre_payload_size = packet_size - header_size
                            self.bwd_payload_sizes.append(gre_payload_size)

                        if packet.haslayer(TCP) and not packet.haslayer(GRE):
                            # Track TCP Flags Backward (only for non-tunneled TCP)
                            self.track_tcp_flags(packet, direction='bwd', flow_id=flow_id)

                        if self.last_bwd_packet_time is not None:
                            self.bwd_inter_arrival_times.append(current_time - self.last_bwd_packet_time)

                        self.last_bwd_packet_time = current_time

                    # Calculate inter-arrival time
                    if self.last_packet_time:
                        self.flow_inter_arrival_times.append(current_time - self.last_packet_time)
                    self.last_packet_time = current_time

                    # Initialize or update flow duration
                    if flow_id not in self.flow_durations:
                        self.flow_durations[flow_id] = [current_time, current_time]
                        self.packets_per_flow[flow_id] = 1
                        self.current_flows += 1  # New flow
                    else:
                        self.flow_durations[flow_id][1] = current_time
                        self.packets_per_flow[flow_id] += 1

                    # Handle IP fragmentation and protocol anomalies
                    if packet[IP].flags != 0 or packet[IP].frag > 0:
                        self.frag_flags += 1

                    # Decode payload safely
                    payload = self.safe_decode_payload(packet)

                    if payload and len(payload) > 0:
                        parts = payload.split('-')
                        if len(parts) > 0:
                            label = parts[0]  # This gets the label part of your payload
                            self.labels.append(label)
                    else:
                        self.labels.append(None)

            except Exception as e:
                self.log_error(f"Error in processing packets: {e}")

        try:
            # Modified filter to include GRE packets (protocol 47)
            sniff(filter="proto 47 or udp or tcp", prn=process_packet, store=0)
        
        except Exception as e:
            self.log_error(f"Sniffing Error: {e}")

    def track_tcp_flags(self, packet, direction, flow_id = None):
        # Helper function to track TCP flags
        if direction == 'fwd':
            if packet[TCP].flags & 0x08:  # PSH flag
                self.psh_flag_count_fwd += 1
            if packet[TCP].flags & 0x20:  # URG flag
                self.urg_flag_count_fwd += 1
            if packet[TCP].flags & 0x01:  # FIN flag
                self.fin_flag_count_fwd += 1
            if packet[TCP].flags & 0x02:  # SYN flag
                self.syn_flag_count_fwd += 1
            if packet[TCP].flags & 0x04:  # RST flag
                self.rst_flag_count_fwd += 1
            if packet[TCP].flags & 0x10:  # ACK flag
                self.ack_flag_count_fwd += 1
            if packet[TCP].flags & 0x80:  # CWE flag
                self.cwe_flag_count_fwd += 1
            if packet[TCP].flags & 0x40:  # ECE flag
                self.ece_flag_count_fwd += 1

        elif direction == 'bwd':
            if packet[TCP].flags & 0x08:  # PSH flag
                self.psh_flag_count_bwd += 1
            if packet[TCP].flags & 0x20:  # URG flag
                self.urg_flag_count_bwd += 1
            if packet[TCP].flags & 0x01:  # FIN flag
                self.fin_flag_count_bwd += 1
            if packet[TCP].flags & 0x04:  # RST flag
                self.rst_flag_count_bwd += 1
            if packet[TCP].flags & 0x10:  # ACK flag
                self.ack_flag_count_bwd += 1
            if packet[TCP].flags & 0x80:  # CWE flag
                self.cwe_flag_count_bwd += 1
            if packet[TCP].flags & 0x40:  # ECE flag
                self.ece_flag_count_bwd += 1

            if packet[TCP].flags & 0x02:  # SYN
                self.syn_flag_count_bwd += 1
                if flow_id :
                    self.syn_packets[flow_id] += 1
            elif flow_id and packet[TCP].flags & 0x12:  # SYN-ACK
                self.syn_ack_packets[flow_id] += 1
            elif flow_id and packet[TCP].flags & 0x10:  # ACK
                if self.syn_packets[flow_id] > 0 and self.syn_ack_packets[flow_id] > 0:
                    self.handshake_completions += 1
                    del self.syn_packets[flow_id]
                    del self.syn_ack_packets[flow_id]

            # Optionally, track half-open connections
            if (packet[TCP].flags & 0x02) and not (packet[TCP].flags & 0x10):
                self.half_open_connections += 1
            

    def safe_decode_payload(self, packet):
        """Enhanced payload decoding with better GRE support and debugging."""
        try:
            payload_data = None
            
            if packet.haslayer(GRE):
                #print("DEBUG: Processing GRE packet")
                gre_layer = packet[GRE]
                
                # Try to get the raw payload from GRE
                if hasattr(gre_layer, 'payload') and gre_layer.payload:
                    # Check if there's a Raw layer in the GRE payload
                    if gre_layer.payload.haslayer(Raw):
                        raw_data = bytes(gre_layer.payload[Raw])
                        #print(f"DEBUG: Found Raw layer in GRE, length: {len(raw_data)}")
                        payload_data = raw_data
                    # Check if the tunneled packet has UDP with payload
                    elif gre_layer.payload.haslayer(UDP):
                        udp_layer = gre_layer.payload[UDP]
                        if hasattr(udp_layer, 'payload') and udp_layer.payload:
                            if udp_layer.payload.haslayer(Raw):
                                raw_data = bytes(udp_layer.payload[Raw])
                                #print(f"DEBUG: Found Raw layer in tunneled UDP, length: {len(raw_data)}")
                                payload_data = raw_data
                            else:
                                raw_data = bytes(udp_layer.payload)
                                #print(f"DEBUG: Found UDP payload, length: {len(raw_data)}")
                                payload_data = raw_data
                    # Check if the tunneled packet has TCP with payload
                    elif gre_layer.payload.haslayer(TCP):
                        tcp_layer = gre_layer.payload[TCP]
                        if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                            if tcp_layer.payload.haslayer(Raw):
                                raw_data = bytes(tcp_layer.payload[Raw])
                                #print(f"DEBUG: Found Raw layer in tunneled TCP, length: {len(raw_data)}")
                                payload_data = raw_data
                            else:
                                raw_data = bytes(tcp_layer.payload)
                                #print(f"DEBUG: Found TCP payload, length: {len(raw_data)}")
                                payload_data = raw_data
                    else:
                        # Try to get raw bytes from the entire GRE payload
                        raw_data = bytes(gre_layer.payload)
                        #print(f"DEBUG: Using entire GRE payload, length: {len(raw_data)}")
                        payload_data = raw_data
                        
            elif packet.haslayer(UDP):
                #print("DEBUG: Processing UDP packet")
                if hasattr(packet[UDP], 'payload') and packet[UDP].payload:
                    if packet[UDP].payload.haslayer(Raw):
                        payload_data = bytes(packet[UDP].payload[Raw])
                        #print(f"DEBUG: Found Raw layer in UDP, length: {len(payload_data)}")
                    else:
                        payload_data = bytes(packet[UDP].payload)
                        #print(f"DEBUG: Found UDP payload, length: {len(payload_data)}")
                        
            elif packet.haslayer(TCP):
                #print("DEBUG: Processing TCP packet")
                if hasattr(packet[TCP], 'payload') and packet[TCP].payload:
                    if packet[TCP].payload.haslayer(Raw):
                        payload_data = bytes(packet[TCP].payload[Raw])
                        #print(f"DEBUG: Found Raw layer in TCP, length: {len(payload_data)}")
                    else:
                        payload_data = bytes(packet[TCP].payload)
                        #print(f"DEBUG: Found TCP payload, length: {len(payload_data)}")
            
            # Try to decode the payload
            if payload_data:
                try:
                    decoded = payload_data.decode('utf-8', errors='ignore').strip()
                    #print(f"DEBUG: Successfully decoded payload: '{decoded}'")
                    return decoded
                except Exception as decode_error:
                    #print(f"DEBUG: UTF-8 decode failed: {decode_error}")
                    # Try with different encodings
                    for encoding in ['ascii', 'latin1']:
                        try:
                            decoded = payload_data.decode(encoding, errors='ignore').strip()
                            #print(f"DEBUG: Successfully decoded with {encoding}: '{decoded}'")
                            return decoded
                        except:
                            continue
                    
                    # If all decoding fails, try to find printable characters
                    printable_chars = ''.join(chr(b) for b in payload_data if 32 <= b <= 126)
                    if printable_chars:
                        #print(f"DEBUG: Extracted printable chars: '{printable_chars}'")
                        return printable_chars
            
            #print("DEBUG: No payload data found")
            return None
            
        except Exception as e:
            print(f"DEBUG: Exception in safe_decode_payload: {e}")
            return None

    def calculate_statistics(self, data):
        """ Calculate common statistics for a given list of numbers. """
        if not data:
            return [0] * 5  # avg, min, max, std, diff_max

        avg = np.mean(data)
        min_val = np.min(data)
        max_val = np.max(data)
        std = np.std(data) if len(data) > 1 else 0
        diff_max = np.max(np.diff(data)) if len(data) > 1 else 0

        return avg, min_val, max_val, std, diff_max

    def aggregate_features(self):
        """Aggregates features from captured packets at specified intervals."""
        while True:
            time.sleep(self.AGG_INTERVAL)
            current_timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            features = self.calculate_features(current_timestamp)

            # Write features to MongoDB
            self.write_to_mongodb(features)

            # Update the aggregated data for the API
            self.last_features = features

            # Reset data for the next aggregation cycle
            self.reset_aggregated_data()

    def get_label(self):
        """Determine the label based on the current collected labels."""
        if self.labels:

            if len(self.labels) > 0 :

                count_labels = Counter(self.labels)
                attack_counts = {label: count for label, count in count_labels.items() if label in ["UDP_FLOOD", "TCP_SYN_FLOOD"]}
                benign_counts = {label: count for label, count in count_labels.items() if label == "BENIGN"}

                if attack_counts :
                    # Otherwise, return the most frequent non-benign label
                    return max(attack_counts, key=attack_counts.get)

                elif benign_counts :
                    return "BENIGN"

        # Default to None if no labels are present
        return None

    def calculate_features(self, current_timestamp):
        """Calculates features for the current aggregation cycle."""
        total_len_fwd_packets = sum(self.fwd_packet_sizes)
        total_len_bwd_packets = sum(self.bwd_packet_sizes)
        packet_drop_rate = (self.packet_drop / self.AGG_INTERVAL) * 100 if self.AGG_INTERVAL > 0 else 0
        # Create a snapshot of the flow durations to avoid modifications during iteration
        flow_durations_snapshot = list(self.flow_durations.values())
        
        # Proceed with the calculation on the snapshot
        flow_durations_list = [end - start for start, end in flow_durations_snapshot]

        # Calculate total bytes and packets for flows
        total_flow_bytes = sum(self.flow_bytes.values())
        total_flow_packets = sum(self.flow_packets.values())
        flow_bytes_per_sec = total_flow_bytes / self.AGG_INTERVAL if self.AGG_INTERVAL > 0 else 0
        flow_packets_per_sec = total_flow_packets / self.AGG_INTERVAL if self.AGG_INTERVAL > 0 else 0

        # Calculate down/up ratio
        down_up_ratio = (self.bwd_packet_count / self.fwd_packet_count) if self.fwd_packet_count > 0 else 0

        # IP/Port Entropies Calculation
        src_ip_entropy = self.calculate_entropy(self.source_ips)
        src_port_entropy = self.calculate_entropy(self.source_ports)
        dest_port_entropy = self.calculate_entropy(self.dest_ports)
        udp_src_port_entropy = self.calculate_entropy(self.udp_source_ports)
        udp_dest_port_entropy = self.calculate_entropy(self.udp_dest_ports)
        tcp_src_port_entropy = self.calculate_entropy(self.tcp_source_ports)
        tcp_dest_port_entropy = self.calculate_entropy(self.tcp_dest_ports)
        
        # GRE-specific entropies
        gre_src_ip_entropy = self.calculate_entropy(self.gre_source_ips)
        gre_dest_ip_entropy = self.calculate_entropy(self.gre_dest_ips)
        gre_protocol_entropy = self.calculate_entropy(self.gre_protocol_types)
        gre_tunneled_protocol_entropy = self.calculate_entropy(self.gre_tunneled_protocols)

        unique_source_ips = len(list(set(self.source_ips)))
        unique_udp_source_ports = len(list(set(self.udp_source_ports)))
        unique_udp_dest_ports = len(list(set(self.udp_dest_ports)))
        unique_tcp_source_ports = len(list(set(self.tcp_source_ports)))
        unique_tcp_dest_ports = len(list(set(self.tcp_dest_ports)))
        unique_gre_source_ips = len(list(set(self.gre_source_ips)))
        unique_gre_dest_ips = len(list(set(self.gre_dest_ips)))

        active_flows_to_unique_src_ips = (self.current_flows / unique_source_ips) if unique_source_ips > 0 else 0

        # Calculate statistics
        avg_fwd_pkt_size, min_fwd_pkt_size, max_fwd_pkt_size, std_fwd_pkt_size, diff_max_fwd_pkt_size = self.calculate_statistics(self.fwd_packet_sizes)
        avg_bwd_pkt_size, min_bwd_pkt_size, max_bwd_pkt_size, std_bwd_pkt_size, diff_max_bwd_pkt_size = self.calculate_statistics(self.bwd_packet_sizes)
        avg_fwd_payload_size, min_fwd_payload_size, max_fwd_payload_size, std_fwd_payload_size, diff_max_fwd_payload_size = self.calculate_statistics(self.fwd_payload_sizes)
        avg_bwd_payload_size, min_bwd_payload_size, max_bwd_payload_size, std_bwd_payload_size, diff_max_bwd_payload_size = self.calculate_statistics(self.bwd_payload_sizes)
        avg_fwd_header_size, min_fwd_header_size, max_fwd_header_size, std_fwd_header_size, diff_max_fwd_header_size = self.calculate_statistics(self.fwd_header_sizes)
        avg_bwd_header_size, min_bwd_header_size, max_bwd_header_size, std_bwd_header_size, diff_max_bwd_header_size = self.calculate_statistics(self.bwd_header_sizes)
        avg_inter_arrival_time, min_inter_arrival_time, max_inter_arrival_time, std_inter_arrival_time, diff_max_inter_arrival_time = self.calculate_statistics(self.flow_inter_arrival_times)
        avg_fwd_iat, min_fwd_iat, max_fwd_iat, std_fwd_iat, diff_max_fwd_iat = self.calculate_statistics(self.fwd_inter_arrival_times)
        avg_bwd_iat, min_bwd_iat, max_bwd_iat, std_bwd_iat, diff_max_bwd_iat = self.calculate_statistics(self.bwd_inter_arrival_times)
        avg_flow_duration, min_flow_duration, max_flow_duration, std_flow_duration, diff_max_flow_duration = self.calculate_statistics(flow_durations_list)
        avg_packets_per_flow, min_packets_per_flow, max_packets_per_flow, std_packets_per_flow, diff_max_packets_per_flow = self.calculate_statistics(list(self.packets_per_flow.values()))

        features = {
            'timestamp': current_timestamp,
            'protocol': self.protocol,
            'tcp_psh_fwd_count': self.psh_flag_count_fwd,
            'tcp_psh_bwd_count': self.psh_flag_count_bwd,
            'tcp_urg_fwd_count': self.urg_flag_count_fwd,
            'tcp_urg_bwd_count': self.urg_flag_count_bwd,
            'tcp_fin_fwd_count': self.fin_flag_count_fwd,
            'tcp_fin_bwd_count': self.fin_flag_count_bwd,
            'tcp_syn_fwd_count': self.syn_flag_count_fwd,
            'tcp_syn_bwd_count': self.syn_flag_count_bwd,
            'tcp_rst_fwd_count': self.rst_flag_count_fwd,
            'tcp_rst_bwd_count': self.rst_flag_count_bwd,
            'tcp_ack_fwd_count': self.ack_flag_count_fwd,
            'tcp_ack_bwd_count': self.ack_flag_count_bwd,
            'tcp_cwe_fwd_count': self.cwe_flag_count_fwd,
            'tcp_cwe_bwd_count': self.cwe_flag_count_bwd,
            'tcp_ece_fwd_count': self.ece_flag_count_fwd,
            'tcp_ece_bwd_count': self.ece_flag_count_bwd,
            'half_open_connections': self.half_open_connections,
            'handshake_completions': self.handshake_completions,
            'fwd_packet_count': self.fwd_packet_count,
            'bwd_packet_count': self.bwd_packet_count,
            'total_len_fwd_packets': total_len_fwd_packets,
            'total_len_bwd_packets': total_len_bwd_packets,
            'avg_fwd_pkt_size': avg_fwd_pkt_size,
            'min_fwd_pkt_size': min_fwd_pkt_size,
            'max_fwd_pkt_size': max_fwd_pkt_size,
            'std_fwd_pkt_size': std_fwd_pkt_size,
            'diff_max_fwd_pkt_size': diff_max_fwd_pkt_size,
            'avg_bwd_pkt_size': avg_bwd_pkt_size,
            'min_bwd_pkt_size': min_bwd_pkt_size,
            'max_bwd_pkt_size': max_bwd_pkt_size,
            'std_bwd_pkt_size': std_bwd_pkt_size,
            'diff_max_bwd_pkt_size': diff_max_bwd_pkt_size,
            'avg_fwd_payload_size': avg_fwd_payload_size,
            'min_fwd_payload_size': min_fwd_payload_size,
            'max_fwd_payload_size': max_fwd_payload_size,
            'std_fwd_payload_size': std_fwd_payload_size,
            'diff_max_fwd_payload_size': diff_max_fwd_payload_size,
            'avg_bwd_payload_size': avg_bwd_payload_size,
            'min_bwd_payload_size': min_bwd_payload_size,
            'max_bwd_payload_size': max_bwd_payload_size,
            'std_bwd_payload_size': std_bwd_payload_size,
            'diff_max_bwd_payload_size': diff_max_bwd_payload_size,
            'avg_fwd_header_size': avg_fwd_header_size,
            'min_fwd_header_size': min_fwd_header_size,
            'max_fwd_header_size': max_fwd_header_size,
            'std_fwd_header_size': std_fwd_header_size,
            'diff_max_fwd_header_size': diff_max_fwd_header_size,
            'avg_bwd_header_size': avg_bwd_header_size,
            'min_bwd_header_size': min_bwd_header_size,
            'max_bwd_header_size': max_bwd_header_size,
            'std_bwd_header_size': std_bwd_header_size,
            'diff_max_bwd_header_size': diff_max_bwd_header_size,
            'init_win_bytes': self.init_win_bytes,
            'frag_flags': self.frag_flags,
            'proto_anomalies': self.proto_anomalies,
            'avg_inter_arrival_time': avg_inter_arrival_time,
            'min_inter_arrival_time': min_inter_arrival_time,
            'max_inter_arrival_time': max_inter_arrival_time,
            'std_inter_arrival_time': std_inter_arrival_time,
            'diff_max_inter_arrival_time': diff_max_inter_arrival_time,
            'avg_fwd_iat': avg_fwd_iat,
            'min_fwd_iat': min_fwd_iat,
            'max_fwd_iat': max_fwd_iat,
            'std_fwd_iat': std_fwd_iat,
            'diff_max_fwd_iat': diff_max_fwd_iat,
            'avg_bwd_iat': avg_bwd_iat,
            'min_bwd_iat': min_bwd_iat,
            'max_bwd_iat': max_bwd_iat,
            'std_bwd_iat': std_bwd_iat,
            'diff_max_bwd_iat': diff_max_bwd_iat,
            'avg_flow_duration': avg_flow_duration,
            'min_flow_duration': min_flow_duration,
            'max_flow_duration': max_flow_duration,
            'std_flow_duration': std_flow_duration,
            'diff_max_flow_duration': diff_max_flow_duration,
            'avg_packets_per_flow': avg_packets_per_flow,
            'min_packets_per_flow': min_packets_per_flow,
            'max_packets_per_flow': max_packets_per_flow,
            'std_packets_per_flow': std_packets_per_flow,
            'diff_max_packets_per_flow': diff_max_packets_per_flow,
            'flow_bytes_per_sec': flow_bytes_per_sec,
            'flow_packets_per_sec': flow_packets_per_sec,
            'down_up_ratio': down_up_ratio,
            'src_ip_entropy': src_ip_entropy,
            'src_port_entropy': src_port_entropy,
            'dest_port_entropy': dest_port_entropy,
            'udp_src_port_entropy': udp_src_port_entropy,
            'udp_dest_port_entropy': udp_dest_port_entropy,
            'tcp_src_port_entropy': tcp_src_port_entropy,
            'tcp_dest_port_entropy': tcp_dest_port_entropy,
            'unique_source_ips': unique_source_ips,
            'unique_udp_source_ports': unique_udp_source_ports,
            'unique_udp_dest_ports': unique_udp_dest_ports,
            'unique_tcp_source_ports': unique_tcp_source_ports,
            'unique_tcp_dest_ports': unique_tcp_dest_ports,
            'active_flows': self.current_flows,
            'active_flows_to_unique_src_ips': active_flows_to_unique_src_ips,
            'cpu_util': self.cpu_util,
            'mem_util': self.mem_util,
            'fd_util': self.fd_util,
            'io_wait': self.io_wait,
            'load_avg': self.load_avg,
            'packet_drop_rate': packet_drop_rate,
            
            # GRE-specific features
            'gre_checksum_present': self.gre_checksum_present,
            'gre_routing_present': self.gre_routing_present,
            'gre_key_present': self.gre_key_present,
            'gre_sequence_present': self.gre_sequence_present,
            'gre_strict_source_route': self.gre_strict_source_route,
            'gre_recursion_control': self.gre_recursion_control,
            'gre_version_anomalies': self.gre_version_anomalies,
            'gre_src_ip_entropy': gre_src_ip_entropy,
            'gre_dest_ip_entropy': gre_dest_ip_entropy,
            'gre_protocol_entropy': gre_protocol_entropy,
            'gre_tunneled_protocol_entropy': gre_tunneled_protocol_entropy,
            'unique_gre_source_ips': unique_gre_source_ips,
            'unique_gre_dest_ips': unique_gre_dest_ips,
            
            'label': self.get_label()
        }

        return features
    
    def reset_aggregated_data(self):
        """Reset all aggregated data for the next cycle."""
        # Reset packet counts and sizes
        self.fwd_packet_count, self.bwd_packet_count = 0, 0
        self.fwd_packet_sizes, self.bwd_packet_sizes = [], []
        self.fwd_payload_sizes, self.bwd_payload_sizes = [], []
        self.fwd_header_sizes, self.bwd_header_sizes = [], []
        
        # Reset GRE-specific variables
        self.gre_checksum_present = 0
        self.gre_routing_present = 0
        self.gre_key_present = 0
        self.gre_sequence_present = 0
        self.gre_strict_source_route = 0
        self.gre_recursion_control = 0
        self.gre_version_anomalies = 0
        self.gre_protocol_types = []
        self.gre_tunneled_protocols = []
        
        # Reset other variables
        self.init_win_bytes = 0
        self.packet_drop = 0
        self.frag_flags, self.proto_anomalies = 0, 0
        self.flow_inter_arrival_times, self.fwd_inter_arrival_times, self.bwd_inter_arrival_times = [], [], []
        
        # Reset TCP flags
        self.psh_flag_count_fwd, self.urg_flag_count_fwd = 0, 0
        self.fin_flag_count_fwd, self.syn_flag_count_fwd = 0, 0
        self.rst_flag_count_fwd, self.ack_flag_count_fwd = 0, 0
        self.cwe_flag_count_fwd, self.ece_flag_count_fwd = 0, 0
        self.psh_flag_count_bwd, self.urg_flag_count_bwd = 0, 0
        self.fin_flag_count_bwd, self.syn_flag_count_bwd = 0, 0
        self.rst_flag_count_bwd, self.ack_flag_count_bwd = 0, 0
        self.cwe_flag_count_bwd, self.ece_flag_count_bwd = 0, 0
        
        # Reset SYN flood variables
        self.half_open_connections = 0
        self.handshake_completions = 0
        self.syn_packets.clear()
        self.syn_ack_packets.clear()
        
        # Reset IP/Port lists
        self.source_ips, self.source_ports, self.dest_ports = [], [], []
        self.udp_source_ports, self.udp_dest_ports = [], []
        self.tcp_source_ports, self.tcp_dest_ports = [], []
        self.gre_source_ips, self.gre_dest_ips = [], []
        
        # Reset flow variables
        self.flow_durations, self.packets_per_flow, self.flow_bytes, self.flow_packets = {}, {}, {}, {}
        self.current_flows = 0

        # Reset system metrics
        self.cpu_util = 0
        self.mem_util = 0
        self.fd_util = 0
        self.io_wait = 0
        self.load_avg = 0

        # Reset the protocol attribute
        self.protocol = ""

        # Reset labels
        self.labels = []
        
        # Reset timing variables
        self.last_packet_time, self.last_fwd_packet_time, self.last_bwd_packet_time = None, None, None

    def calculate_entropy(self, values):
        """ Calculate the entropy of a list of values. """
        if not values :
            return 0
        value_counts = Counter(values)
        probabilities = [count / len(values) for count in value_counts.values()]
        return -sum(p * math.log2(p) for p in probabilities)


    def log_error(self, message):
        """Logs error messages to a log file."""
        log_dir = os.path.expanduser('~/traffic_flood_detection/logs/')
        os.makedirs(log_dir, exist_ok=True)  # Create the log directory if it doesn't exist
        log_file_path = os.path.join(log_dir, 'capture_errors.log')
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"{datetime.utcnow()} - {message}\n")

    async def websocket_handler(self, websocket):
        """Handles a WebSocket connection."""
        self.CONNECTIONS.add(websocket)
        
        try:
            await websocket.send("Connected to WebSocket server!")
            asyncio.create_task(self.send_features(websocket))

            while True:
                await asyncio.sleep(1)  # Keep the connection alive
                
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")
        finally:
            self.CONNECTIONS.remove(websocket)

    async def send_features(self, websocket):
        """Handles sending features to the connected WebSocket client."""
        while True:
            await asyncio.sleep(self.AGG_INTERVAL)  # Wait for the aggregation interval
            if self.last_features:
                try:
                    # Convert last_features to native Python types (to avoid np.int64 serialization issues)
                    json_features = json.dumps(self.last_features, default=lambda o: int(o) if isinstance(o, np.integer) else float(o) if isinstance(o, np.floating) else o)
                    await websocket.send(json_features)
                except websockets.exceptions.ConnectionClosed:
                    print("Connection closed while sending features")
                    break  # Exit the loop if the connection is closed

    def start_websocket_server(self):
        """Starts the WebSocket server."""
        start_server = websockets.serve(self.websocket_handler, "0.0.0.0", 8765)
        asyncio.get_event_loop().run_until_complete(start_server)
        print("WebSocket server started on ws://0.0.0.0:8765")
        asyncio.get_event_loop().run_forever()

def run_websocket_server(detector):
    """Run the WebSocket server in an asyncio event loop."""
    loop = asyncio.new_event_loop()  # Create a new event loop
    asyncio.set_event_loop(loop)      # Set the new event loop as the current one
    loop.run_until_complete(detector.start_websocket_server())  # Run the server
    loop.close()

if __name__ == "__main__":
    detector = FloodDetector()
    threading.Thread(target=detector.monitor_system_metrics, daemon=True).start()
    threading.Thread(target=detector.aggregate_features, daemon=True).start()
    threading.Thread(target=run_websocket_server, args=(detector,), daemon=True).start()

    detector.capture_packets()