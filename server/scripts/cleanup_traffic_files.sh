#!/bin/bash

# Function to check if a process is running
is_process_running() {
    local pid=$1
    if [ -e "/proc/$pid" ]; then
        return 0  # Process is running
    else
        return 1  # Process is not running
    fi
}

# Function to safely remove a PID file and its associated log file
cleanup_files() {
    local pid_file=$1
    local log_file="${pid_file%.pid}.log"
    
    # Check if PID file exists
    if [ -f "$pid_file" ]; then
        # Read PID from file
        pid=$(cat "$pid_file")
        
        # Check if process is running
        if is_process_running "$pid"; then
            echo "Process $pid is still running, skipping $pid_file"
            return
        fi
        
        # Process is not running, safe to remove files
        echo "Removing $pid_file and $log_file"
        rm -f "$pid_file"
        rm -f "$log_file"
    fi
}

# Main cleanup process
echo "Starting cleanup of traffic files..."

# Find all traffic PID files
for pid_file in /tmp/traffic_*.pid; do
    if [ -f "$pid_file" ]; then
        cleanup_files "$pid_file"
    fi
done

# Remove traffic_shaping.lock if it exists
if [ -f "/tmp/traffic_shaping.lock" ]; then
    echo "Removing traffic_shaping.lock"
    rm -f "/tmp/traffic_shaping.lock"
fi

echo "Cleanup completed" 