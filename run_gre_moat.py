#!/usr/bin/env python3
import os
import sys
from dotenv import load_dotenv
from gre_setup import GRESetup

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        sys.exit(1)

    # Load environment variables
    load_dotenv()

    # Get required environment variables
    interface = os.getenv('INTERFACE')
    traffic_gen_ip = os.getenv('MONGODB_TGEN_IP')
    king_ip = os.getenv('SSH_HOST_PRIVATE_IP')  # Using standard uppercase with underscores format

    if not interface:
        print("INTERFACE environment variable is required")
        sys.exit(1)
    if not traffic_gen_ip:
        print("MONGODB_TGEN_IP environment variable is required")
        sys.exit(1)
    if not king_ip:
        print("SSH_HOST_PRIVATE_IP environment variable is required")
        sys.exit(1)

    # Set up GRE tunnel
    gre_setup = GRESetup(
        node_type="moat",
        private_ip=king_ip,  # Use the moat's private IP from SSH_HOST_PRIVATE_IP
        interface=interface
    )

    print(f"Setting up GRE tunnel with King IP: {king_ip} and Traffic Generator IP: {traffic_gen_ip}")
    success = gre_setup.moat(king_ip, [traffic_gen_ip])
    
    if not success:
        print("Failed to set up GRE tunnel")
        sys.exit(1)
    
    print("GRE tunnel setup completed successfully")

if __name__ == "__main__":
    main() 