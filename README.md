<picture>
    <source srcset="./assets/shugo_white.png" media="(prefers-color-scheme: dark)">
    <source srcset="./assets/shugo_black.png" media="(prefers-color-scheme: light)">
    <img src="./assets/shugo_black.png" alt="Shugo Logo">
</picture>



<div align="center">

# **Δataprox: SN91** <!-- omit in toc -->
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

DataProx is a modern, production-grade open-source platform developed by Shugo Labs for orchestrating, monitoring, and managing distributed network traffic generation and feature collection. It provides a web dashboard and robust backend for launching, tracking, and cleaning up traffic generator and data collection jobs across multiple remote machines.

---

## Features

- **Traffic Generation**: Launch, monitor, and stop synthetic traffic jobs on remote hosts.
- **Data Collection**: Start and manage feature collection jobs, storing results in MongoDB.
- **Automatic GRE Tunnel Setup**: Ensures GRE tunnels are configured before any job.
- **Real-Time Logs**: View logs for each job in the dashboard.
- **Process Management**: Clean up orphaned jobs and files.
- **Multi-Node Support**: Manage many remote machines from a single dashboard.

---

## Repository Structure

```
dataprox/
├── server/                # Node.js/Express backend API
├── src/                   # React frontend (client)
├── TrafficGenerator/      # Traffic generation scripts (Python, Bash)
│   ├── run_traffic.sh
│   ├── traffic_generator_training.py
│   └── generate_playlist.py
├── TrafficLogger/         # Data collection scripts (Python)
│   └── collect_features.py
├── gre_setup.py           # Shared GRE tunnel setup logic (Python)
├── run_gre_moat.py        # (Optional) GRE tunnel runner
└── README.md
```

---

## Prerequisites

- **Node.js** v16+ (for backend/frontend)
- **Python** 3.8+ (on all remote machines)
- **MongoDB** (for data collection)
- **SSH** access (with password or key) to all remote machines
- **sudo/root** privileges on remote machines (for GRE setup)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/shugo-labs/dataprox.git
cd dataprox
```

### 2. Install dependencies & build the frontend

```bash
npm install && npm run build
```

---

## Configuration

### Backend

- Create a `.env` file in `server/` if you want to override the default port:
  ```
  PORT=3001
  ```

### MongoDB

- Ensure you have a running MongoDB instance.
- You will provide the connection string, database, and collection via the dashboard UI when starting a data collection job.

### Remote Machines

- No manual setup required! The backend will:
  - Clone/update the dataprox repo on each remote machine.
  - Install all required Python and system packages.
  - Set up GRE tunnels as needed.

---

## Usage

### 1. Start the backend server

```bash
cd server && npm start
```

- The dashboard will be available at [http://localhost:3001](http://localhost:3001)

---

## Traffic Generation

### How to Use

- Navigate to the Traffic Generator section in the dashboard.
- Configure the following:
  - SSH connection details (host, username, password/key)
  - Private Network interface
  - Total duration
  - Moat IP addresses (public and private)
  - Traffic generator Private IP address
- Click "Start" to begin traffic generation.
- Monitor logs in real-time.
- Use "Stop" to terminate the instance.

---

## Data Collection

### How to Use

- Navigate to the Data Collection section in the dashboard.
- Configure the following:
  - SSH connection details
  - Private Network interface of the receiver machine (Moat)
  - Traffic generator IP addresses
  - MongoDB connection string
  - Database and collection names

- Click "Start" to begin data collection.
- Monitor logs in real-time.
- Use "Stop" to terminate the instance.

---

## GRE Tunnel Setup

- The GRE tunnel is set up automatically by the backend before any job starts.
- The shared logic is in `gre_setup.py`.
- The script reads all required variables from the `.env` file.

---

## Process Management & Cleanup

- The dashboard allows you to stop individual or all jobs.
- Orphaned log and PID files are cleaned up automatically.
- You can also use the "Cleanup" button in the dashboard to remove stale files.

---

## Security

- All SSH credentials are handled securely and never stored in plaintext.
- Only the required environment variables are written to the remote `.env` file.
- Root access is required only for GRE tunnel setup.

---

## Troubleshooting

- **GRE tunnel setup fails**: Ensure the remote user has sudo privileges and the correct interface/IPs are provided.
- **MongoDB connection fails**: Double-check your URI, database, and collection names.
- **Traffic/data jobs not starting**: Check the logs in the dashboard for error messages.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your fork
5. Open a Pull Request

---

## License

Licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).

---

## Support

For support, open an issue on GitHub or contact the maintainer.
