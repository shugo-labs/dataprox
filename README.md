
<picture>
    <source srcset="./assets/shugo_white.png" media="(prefers-color-scheme: dark)">
    <source srcset="./assets/shugo_black.png" media="(prefers-color-scheme: light)">
    <img src="./assets/shugo_black.png" alt="Shugo Logo">
</picture>



<div align="center">

# **DBprox: SN91** <!-- omit in toc -->
[![Discord Chat](https://img.shields.io/discord/308323056592486420.svg)](https://discord.gg/bittensor)
[![Creative Commons Badge](https://img.shields.io/badge/Creative%20Commons-ED592F?logo=creativecommons&logoColor=fff&style=for-the-badge)](https://creativecommons.org/licenses/by-nc/4.0/deed.en)

---

### The Data Collection Framework built for Tensorprox <!-- omit in toc -->

[Discord](https://discord.gg/bittensor) • [Taostats](https://taostats.io/) • [Linkedin](https://www.linkedin.com/company/105804417/admin/dashboard/) • [Twitter](https://x.com/shugoio)

</div>

---

This repository is the **data collection codebase for Bittensor Subnet 91**. To learn more about the Bittensor project and the underlying mechanics, [read here.](https://docs.bittensor.com/)

<br/>
<div align="left">

# Overview

DBprox is a comprehensive data collection tool suite designed to provide a ready-to-use framework for data generation/collection which will be used to build DDoS protection models. 

This repository provides infrastructure for:
    -> Synthetic Attack Generation: Creating realistic traffic patterns for testing DDoS protection systems
    -> Traffic Feature Collection: Capturing network traffic characteristics to feed ML/rule based detection models.

It contains two primary components for traffic generation and traffic feature collection.

# Repository Structure

```
data-collection/
├── TrafficGenerator/          # Traffic generation component
│   ├── traffic_generator_training.py
│   ├── generate_playlist.py
│   ├── gre_setup.py
│   └── run_traffic.sh        # Main execution script
├── TrafficLogger/            # Traffic logging and feature collection
│   ├── collect_features.py
│   └── run_data_collection.sh # Setup and execution script
│── .env.example #MongoDB inputs
└── README.md
```

# Components

## Traffic Generator

The TrafficGenerator component is designed to run on tgen (traffic generation) machines and simulate various network traffic patterns.

**Key Features:**

* GRE tunnel setup for network isolation  
* Playlist-based traffic generation  
* Configurable traffic patterns and duration  
* Support for multiple network interfaces 

**Dependencies:**

- Python 3.10
- faker
- scapy
- pycryptodome

## Traffic Logger

The TrafficLogger component captures network traffic features and stores them in a MongoDB database for analysis and model training.

**Key Features:**

* Real-time traffic feature extraction
* MongoDB integration for data persistence
* System monitoring capabilities
* Process management with PM2

**Dependencies:**

- tcpdump, tshark
- sysstat, ifstat, dstat, vnstat
- snmpd
- Python packages: scapy, pandas, numpy, psutil, websockets, asyncio, pymongo, python-dotenv
- Node.js and PM2

# Usage

## TrafficGenerator Setup and Execution

Run the traffic generator on tgen machines:

```
./run_traffic.sh <interface> <moat_private_ip> <private_ip> <node_index> <total_duration>
```

**Parameters:**

- interface: Network interface to use
- moat_private_ip: MOAT server private IP address
- private_ip: Local machine private IP
- node_index: Unique identifier for the tgen node
- total_duration: Traffic generation duration in seconds

**What it does:**

* Installs required Python packages
* Sets up GRE tunneling configuration
* Generates a randomized traffic playlist
* Starts traffic generation in background mode

## TrafficLogger Setup and Execution

### Environment Variables
Create a .env file in the TrafficLogger directory with your MongoDB configuration

```
MONGODB_USERNAME=
MONGODB_PASSWORD=
MONGODB_HOST=
MONGODB_DATABASE=
MONGODB_COLLECTION=
```

### Set up traffic logging and feature collection:

```
./run_data_collection.sh
```

**What it does:**

* Updates system packages and installs monitoring tools
* Installs required Python dependencies
* Configures system services (sysstat, snmpd)
* Starts feature collection process using PM2

### Data Output

The TrafficLogger component captures and stores the following traffic features:

* Packet statistics (count, size, timing)
* Protocol distribution
* Flow characteristics
* System resource utilization
* Network interface metrics

Data is stored in MongoDB collections for easy querying and analysis.

# Contribution

We welcome contributions! Detailed guidelines will be published soon.

# License

Licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

## Licensing Terms
- Non-commercial use permitted
- Commercial use restricted to mining/validating within TensorProx subnet
- Commercial licensing requests: Contact **Shugo LTD**

# Contact

Join our [Discord](https://discord.gg/bittensor) for community support and discussions.

---

**Disclaimer**: Tensorprox is an experimental DDoS mitigation network. Always conduct thorough testing in controlled environments.