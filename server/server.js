const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const fs = require('fs');
const WebSocket = require('ws');
const http = require('http');

// Traffic Generator instance tracking
const INSTANCES_FILE = path.join(__dirname, 'running_instances.json');
const runningInstances = new Map(); // Map to store running instances

// Function to verify if a process is still running
async function verifyProcess(sshConfig, pid) {
  try {
    const ssh = await createSSHConnection(sshConfig);
    const result = await ssh.execCommand(`ps -p ${pid} | grep -v TTY`);
    ssh.dispose();
    return result.stdout.trim().length > 0;
  } catch (error) {
    console.error('Error verifying process:', error);
    return false;
  }
}

// Load running instances from file if it exists
async function loadRunningInstances() {
  try {
    if (fs.existsSync(INSTANCES_FILE)) {
      const data = JSON.parse(fs.readFileSync(INSTANCES_FILE, 'utf8'));
      
      // Verify each instance's process
      for (const instance of data) {
        const isRunning = await verifyProcess(instance.sshConfig, instance.pid);
        if (isRunning) {
          runningInstances.set(instance.instanceKey, instance);
        } else {
          console.log(`Instance ${instance.instanceKey} is no longer running`);
        }
      }
      
      // Save the verified instances back to file
      saveRunningInstances();
      console.log('Loaded running instances:', Array.from(runningInstances.values()));
    }
  } catch (error) {
    console.error('Error loading running instances:', error);
  }
}

// Save running instances to file
function saveRunningInstances() {
  try {
    const instances = Array.from(runningInstances.values());
    fs.writeFileSync(INSTANCES_FILE, JSON.stringify(instances, null, 2));
  } catch (error) {
    console.error('Error saving running instances:', error);
  }
}

// Function to add a running instance
function addRunningInstance(nodeIndex, pid, sshConfig) {
  const machineKey = sshConfig.sshHost; // Key for machine
  const instanceKey = `${sshConfig.sshHost}_${nodeIndex}`; // Key for instance

  // Check if machine already has an instance
  for (const [key, instance] of runningInstances.entries()) {
    if (instance.machineIp === sshConfig.sshHost) {
      throw new Error(`Machine ${sshConfig.sshHost} already has a running instance`);
    }
  }

  const instance = {
    pid,
    startTime: new Date(),
    sshConfig,
    status: 'running',
    nodeIndex,
    machineIp: sshConfig.sshHost,
    instanceKey
  };

  runningInstances.set(instanceKey, instance);
  saveRunningInstances();
  return instance;
}

// Function to remove a running instance
function removeRunningInstance(nodeIndex, sshHost) {
  const instanceKey = `${sshHost}_${nodeIndex}`;
  runningInstances.delete(instanceKey);
  saveRunningInstances();
}

// Function to get all running instances
function getRunningInstances() {
  return Array.from(runningInstances.values());
}

// Function to check if a node index is already running on any machine
function isNodeIndexRunning(nodeIndex) {
  for (const [key, instance] of runningInstances.entries()) {
    if (instance.nodeIndex === nodeIndex) {
      return true;
    }
  }
  return false;
}

// Function to check if a machine already has a running instance
function isMachineRunning(sshHost) {
  for (const [key, instance] of runningInstances.entries()) {
    if (instance.machineIp === sshHost) {
      return true;
    }
  }
  return false;
}

const app = express();
const port = process.env.PORT || 3001; // Use environment variable PORT or default to 3002

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from the React app
app.use(express.static(path.join(__dirname, '../build')));

// Create HTTP server
const server = http.createServer(app);

// Create WebSocket server attached to the HTTP server
const wss = new WebSocket.Server({ server });

// Store active log streams
const activeStreams = new Map();

// WebSocket connection handler
wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    if (data.type === 'subscribe' && data.logFile) {
      // Subscribe to log file updates
      if (!activeStreams.has(data.logFile)) {
        const stream = fs.createReadStream(path.join(logsDir, data.logFile), {
          start: fs.statSync(path.join(logsDir, data.logFile)).size
        });
        activeStreams.set(data.logFile, stream);
        
        stream.on('data', (chunk) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'log',
              content: chunk.toString()
            }));
          }
        });
      }
    } else if (data.type === 'unsubscribe' && data.logFile) {
      // Unsubscribe from log file updates
      const stream = activeStreams.get(data.logFile);
      if (stream) {
        stream.destroy();
        activeStreams.delete(data.logFile);
      }
    }
  });

  ws.on('close', () => {
    // Clean up streams when client disconnects
    for (const [logFile, stream] of activeStreams.entries()) {
      stream.destroy();
      activeStreams.delete(logFile);
    }
  });
});

// Helper function to create SSH connection
async function createSSHConnection(sshConfig) {
  const ssh = new NodeSSH();
  try {
    console.log('SSH Connection attempt details:', {
      host: sshConfig.sshHost,
      username: sshConfig.sshUsername,
      hasPassword: !!sshConfig.sshPassword,
      hasKeyPath: !!sshConfig.sshKeyPath,
      keyPath: sshConfig.sshKeyPath
    });

    const config = {
      host: sshConfig.sshHost,
      username: sshConfig.sshUsername,
      readyTimeout: 30000,
      keepaliveInterval: 10000,
      debug: true,
      tryKeyboard: true
    };

    // Add password if provided
    if (sshConfig.sshPassword) {
      config.password = sshConfig.sshPassword;
      console.log('Using password authentication');
    }

    // Add private key if provided
    if (sshConfig.sshKeyPath) {
      try {
        console.log('Attempting to read private key from:', sshConfig.sshKeyPath);
        if (!fs.existsSync(sshConfig.sshKeyPath)) {
          throw new Error(`Private key file does not exist at: ${sshConfig.sshKeyPath}`);
        }
        const keyStats = fs.statSync(sshConfig.sshKeyPath);
        console.log('Key file stats:', {
          size: keyStats.size,
          mode: keyStats.mode,
          uid: keyStats.uid,
          gid: keyStats.gid
        });
        config.privateKey = fs.readFileSync(sshConfig.sshKeyPath, 'utf8');
        console.log('Successfully read private key');
      } catch (error) {
        console.error('Error reading private key:', error);
        throw new Error(`Failed to read private key file: ${error.message}`);
      }
    }

    if (!config.password && !config.privateKey) {
      throw new Error('Neither password nor private key provided for authentication');
    }

    console.log('Attempting SSH connection with config:', {
      ...config,
      password: config.password ? '[REDACTED]' : undefined,
      privateKey: config.privateKey ? '[REDACTED]' : undefined
    });

    await ssh.connect(config);
    console.log('SSH connection established successfully');

    // Test the connection with a simple command
    console.log('Testing connection with echo command...');
    const result = await ssh.execCommand('echo "Connection test"');
    console.log('Test command result:', result);

    return ssh;
  } catch (error) {
    console.error('SSH Connection Error:', {
      message: error.message,
      code: error.code,
      level: error.level,
      stack: error.stack,
      config: {
        host: sshConfig.sshHost,
        username: sshConfig.sshUsername,
        hasPassword: !!sshConfig.sshPassword,
        hasKeyPath: !!sshConfig.sshKeyPath
      }
    });
    throw error;
  }
}

// Get list of log files
app.get('/api/logs', (req, res) => {
  try {
    const files = fs.readdirSync(logsDir)
      .filter(file => file.endsWith('.log'))
      .map(file => {
        const stats = fs.statSync(path.join(logsDir, file));
        return {
          name: file,
          path: `/api/logs/${file}`,
          size: stats.size,
          created: stats.birthtime.toISOString() // Convert to ISO string for proper date handling
        };
      });
    res.json(files);
  } catch (error) {
    console.error('Error listing logs:', error);
    res.status(500).json({ error: 'Failed to list logs' });
  }
});

// Get specific log file content
app.get('/api/logs/:filename', (req, res) => {
  try {
    const filePath = path.join(logsDir, req.params.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Log file not found' });
    }
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ content });
  } catch (error) {
    res.status(500).json({ error: 'Failed to read log file' });
  }
});

// Test SSH connection endpoint for Traffic Generator
app.post('/api/traffic-generator/test-connection', async (req, res) => {
  try {
    console.log('Received test connection request:', {
      host: req.body.sshHost,
      username: req.body.sshUsername,
      hasPassword: !!req.body.sshPassword,
      hasKeyPath: !!req.body.sshKeyPath,
      keyPath: req.body.sshKeyPath
    });

    const ssh = await createSSHConnection(req.body);
    const result = await ssh.execCommand('echo "Connection successful"');
    console.log('Test command result:', result);
    ssh.dispose();
    res.json({ message: 'Connection successful' });
  } catch (error) {
    console.error('SSH Test Error:', {
      message: error.message,
      code: error.code,
      level: error.level,
      stack: error.stack
    });
    res.status(500).json({ 
      error: 'Failed to connect to the traffic generator machine',
      details: error.message 
    });
  }
});

// Test SSH connection endpoint for Data Collection
app.post('/api/data-collection/test-connection', async (req, res) => {
  try {
    const ssh = await createSSHConnection(req.body);
    await ssh.execCommand('echo "Connection successful"');
    ssh.dispose();
    res.json({ message: 'Connection successful' });
  } catch (error) {
    console.error('SSH Test Error:', error);
    res.status(500).json({ error: 'Failed to connect to the data collection machine' });
  }
});

// Traffic Generator endpoint
app.post('/api/traffic-generator/run', async (req, res) => {
  let ssh = null;
  try {
    const { interface, moatPrivateIp, privateIp, nodeIndex, totalDuration, ...sshConfig } = req.body;
    
    // Check if this node index is already running on any machine
    if (isNodeIndexRunning(nodeIndex)) {
      return res.status(400).json({ 
        error: 'Traffic generator with this node index is already running',
        details: `Node index ${nodeIndex} is already in use on another machine`
      });
    }

    // Check if this machine already has a running instance
    if (isMachineRunning(sshConfig.sshHost)) {
      return res.status(400).json({
        error: 'Machine already has a running instance',
        details: `Machine ${sshConfig.sshHost} already has a traffic generator running`
      });
    }

    console.log('Starting traffic generation with config:', {
      interface,
      moatPrivateIp,
      privateIp,
      nodeIndex,
      totalDuration,
      sshHost: sshConfig.sshHost,
      sshUsername: sshConfig.sshUsername
    });

    ssh = await createSSHConnection(sshConfig);
    console.log('SSH connection established');
    
    // Check if TrafficGenerator directory exists
    console.log('Checking TrafficGenerator directory...');
    const checkDir = await ssh.execCommand('ls -la ~/dataprox/TrafficGenerator');
    console.log('Directory check result:', checkDir.stdout);

    if (checkDir.code !== 0) {
      console.log('Cloning TrafficGenerator repository...');
      const cloneResult = await ssh.execCommand('git clone https://github.com/shugo-labs/dataprox/TrafficGenerator.git', {
        cwd: '~/dataprox'
      });
      console.log('Clone result:', cloneResult.stdout, cloneResult.stderr);
    }
    
    // Make sure the script is executable
    console.log('Making script executable...');
    await ssh.execCommand('chmod +x ~/dataprox/TrafficGenerator/run_traffic.sh');
    
    // Create a unique log file name
    const timestamp = new Date().getTime();
    const logFileName = `traffic_${timestamp}.log`;
    const logFilePath = path.join(logsDir, logFileName);
    const remoteLogFile = `/tmp/${logFileName}`;
    
    // Create empty log file first
    console.log('Creating log file...');
    await ssh.execCommand(`touch ${remoteLogFile}`);
    
    // Start tailing the log file BEFORE running the script
    console.log('Starting log tail...');
    const tailCommand = `tail -f ${remoteLogFile}`;
    ssh.execCommand(tailCommand, {
      onStdout: (chunk) => {
        const content = chunk.toString();
        console.log('STDOUT:', content);
        // Write to local log file
        fs.appendFileSync(logFilePath, content);
        // Broadcast to all WebSocket clients
        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'log',
              logFile: logFileName,
              content: content
            }));
          }
        });
      },
      onStderr: (chunk) => {
        const content = chunk.toString();
        console.error('STDERR:', content);
        // Write to local log file
        fs.appendFileSync(logFilePath, content);
        // Broadcast to all WebSocket clients
        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'log',
              logFile: logFileName,
              content: content
            }));
          }
        });
      }
    });

    // Run the traffic generator script with proper process group handling
    console.log('Running traffic generator script...');
    const command = `cd ~/dataprox/TrafficGenerator && bash -c '
      timestamp=$(date +%s)
      pidfile="/tmp/traffic_${timestamp}.pid"
      logfile="${remoteLogFile}"

      # Start the traffic generator with nohup and in background
      nohup bash run_traffic.sh ${interface} ${moatPrivateIp} ${privateIp} ${nodeIndex} ${totalDuration} > "$logfile" 2>&1 &
      echo $! > "$pidfile"
    '`;

    // Execute the command
    const result = await ssh.execCommand(command);
    console.log('Script execution result:', result);

    // Get the PID
    const pidResult = await ssh.execCommand(`cat /tmp/traffic_${timestamp}.pid`);
    const pid = pidResult.stdout.trim();
    console.log('Process PID:', pid);

    // Add to running instances
    const instance = addRunningInstance(nodeIndex, pid, sshConfig);

    // Check if the process is running
    console.log('Checking if process is running...');
    const checkProcess = await ssh.execCommand(`ps -p ${pid} | grep -v TTY`);
    console.log('Process check result:', checkProcess.stdout);

    // Don't dispose of SSH connection - we need it for the tail command
    res.json({ 
      message: 'Traffic generation started successfully',
      details: {
        stdout: result.stdout,
        stderr: result.stderr,
        processStatus: checkProcess.stdout,
        pid: pid,
        logFile: `/api/logs/${logFileName}`,
        nodeIndex: nodeIndex,
        instance: instance
      }
    });
  } catch (error) {
    console.error('Traffic Generator Error:', error);
    if (ssh) {
      ssh.dispose();
    }
    res.status(500).json({ 
      error: 'Failed to start traffic generation',
      details: error.message,
      stack: error.stack
    });
  }
});

// Get running instances endpoint
app.get('/api/traffic-generator/instances', (req, res) => {
  try {
    const instances = getRunningInstances();
    res.json({ instances });
  } catch (error) {
    console.error('Error getting running instances:', error);
    res.status(500).json({ error: 'Failed to get running instances' });
  }
});

// Stop traffic generator endpoint
app.post('/api/traffic-generator/stop', async (req, res) => {
  let ssh = null;
  try {
    const { pid, nodeIndex, sshHost, sshUsername, sshPassword, sshKeyPath } = req.body;
    
    // Validate required SSH credentials
    if (!sshHost || !sshUsername || (!sshPassword && !sshKeyPath)) {
      return res.status(400).json({
        error: 'Missing required SSH credentials',
        details: 'SSH host, username, and either password or key path are required to stop processes'
      });
    }

    // First verify if the process is still running
    const sshConfig = {
      sshHost,
      sshUsername,
      sshPassword,
      sshKeyPath
    };

    // Test SSH connection before proceeding
    try {
      ssh = await createSSHConnection(sshConfig);
      console.log('SSH connection established for stop operation');
    } catch (error) {
      return res.status(401).json({
        error: 'Failed to establish SSH connection',
        details: 'Invalid SSH credentials or connection failed'
      });
    }

    if (pid) {
      const isRunning = await verifyProcess(sshConfig, pid);
      if (!isRunning) {
        // Process is not running, just remove from our tracking
        if (nodeIndex) {
          removeRunningInstance(nodeIndex, sshHost);
        }
        return res.json({ 
          message: 'Process was not running, removed from tracking',
          stoppedPid: pid
        });
      }
    }
    
    if (pid) {
      // Stop specific process by PID
      try {
        await ssh.execCommand(`kill ${pid}`);
        // Verify the process was stopped
        const checkResult = await ssh.execCommand(`ps -p ${pid} | grep -v TTY`);
        if (checkResult.stdout.trim().length === 0) {
          // Process was successfully stopped
          if (nodeIndex) {
            removeRunningInstance(nodeIndex, sshHost);
          }
        } else {
          // Process is still running, try force kill
          await ssh.execCommand(`kill -9 ${pid}`);
          if (nodeIndex) {
            removeRunningInstance(nodeIndex, sshHost);
          }
        }
      } catch (error) {
        console.error('Error stopping process:', error);
        // Even if there's an error, remove from tracking
        if (nodeIndex) {
          removeRunningInstance(nodeIndex, sshHost);
        }
      }
    } else {
      // Kill all traffic generator processes
      try {
        await ssh.execCommand('pkill -f run_traffic.sh');
        // Clear all running instances for this machine
        for (const [key, instance] of runningInstances.entries()) {
          if (instance.machineIp === sshHost) {
            runningInstances.delete(key);
          }
        }
        saveRunningInstances();
      } catch (error) {
        console.error('Error stopping all processes:', error);
        // Even if there's an error, remove from tracking
        for (const [key, instance] of runningInstances.entries()) {
          if (instance.machineIp === sshHost) {
            runningInstances.delete(key);
          }
        }
        saveRunningInstances();
      }
    }
    
    ssh.dispose();
    res.json({ 
      message: 'Traffic generator stopped successfully',
      stoppedPid: pid || 'all'
    });
  } catch (error) {
    console.error('Stop Traffic Generator Error:', error);
    if (ssh) {
      ssh.dispose();
    }
    // Even if there's an error, try to remove from tracking
    if (req.body.nodeIndex && req.body.sshHost) {
      removeRunningInstance(req.body.nodeIndex, req.body.sshHost);
    }
    res.status(500).json({ 
      error: 'Failed to stop traffic generator',
      details: error.message
    });
  }
});

// Cleanup endpoint for stopping tail process
app.post('/api/traffic-generator/cleanup', async (req, res) => {
  let ssh = null;
  try {
    const { pid, sshHost, sshUsername, sshPassword, sshKeyPath } = req.body;
    
    ssh = await createSSHConnection({
      sshHost,
      sshUsername,
      sshPassword,
      sshKeyPath
    });
    
    // Kill the tail process
    await ssh.execCommand(`kill ${pid}`);
    
    ssh.dispose();
    res.json({ message: 'Cleanup completed successfully' });
  } catch (error) {
    console.error('Cleanup Error:', error);
    if (ssh) {
      ssh.dispose();
    }
    res.status(500).json({ error: 'Failed to cleanup processes' });
  }
});

// Delete log file endpoint
app.delete('/api/traffic-generator/logs/:filename', (req, res) => {
  try {
    const filePath = path.join(logsDir, req.params.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Log file not found' });
    }
    fs.unlinkSync(filePath);
    res.json({ message: 'Log file deleted successfully' });
  } catch (error) {
    console.error('Error deleting log file:', error);
    res.status(500).json({ error: 'Failed to delete log file' });
  }
});

// Initialize server
loadRunningInstances().then(() => {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});