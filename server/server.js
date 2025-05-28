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
const DATA_COLLECTION_INSTANCES_FILE = path.join(__dirname, 'running_data_collection.json');
const runningInstances = new Map(); // Map to store running instances
const runningDataCollection = new Map(); // Map to store running data collection instances

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

// Function to verify all running instances
async function verifyAllInstances() {
  const instancesToRemove = [];
  
  for (const [key, instance] of runningInstances.entries()) {
    try {
      const isRunning = await verifyProcess(instance.sshConfig, instance.pid);
      if (!isRunning) {
        instancesToRemove.push(key);
      }
    } catch (error) {
      console.error(`Error verifying instance ${key}:`, error);
      instancesToRemove.push(key);
    }
  }

  // Remove stopped instances
  for (const key of instancesToRemove) {
    runningInstances.delete(key);
  }

  if (instancesToRemove.length > 0) {
    saveRunningInstances();
  }

  return instancesToRemove.length > 0;
}

// Load running data collection instances from file if it exists
async function loadDataCollectionInstances() {
  try {
    if (fs.existsSync(DATA_COLLECTION_INSTANCES_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_COLLECTION_INSTANCES_FILE, 'utf8'));
      
      // Verify each instance's process
      for (const instance of data) {
        const isRunning = await verifyProcess(instance.sshConfig, instance.pid);
        if (isRunning) {
          runningDataCollection.set(instance.instanceKey, instance);
        } else {
          console.log(`Data Collection instance ${instance.instanceKey} is no longer running`);
        }
      }
      
      // Save the verified instances back to file
      saveDataCollectionInstances();
      console.log('Loaded running data collection instances:', Array.from(runningDataCollection.values()));
    }
  } catch (error) {
    console.error('Error loading running data collection instances:', error);
  }
}

// Save running data collection instances to file
function saveDataCollectionInstances() {
  try {
    const instances = Array.from(runningDataCollection.values());
    fs.writeFileSync(DATA_COLLECTION_INSTANCES_FILE, JSON.stringify(instances, null, 2));
  } catch (error) {
    console.error('Error saving running data collection instances:', error);
  }
}

// Function to add a running data collection instance
function addDataCollectionInstance(pid, sshConfig) {
  const instanceKey = sshConfig.sshHost; // Key for instance (one per machine)

  // Check if machine already has an instance
  if (runningDataCollection.has(instanceKey)) {
    throw new Error(`Machine ${sshConfig.sshHost} already has a running data collection instance`);
  }

  const instance = {
    pid,
    startTime: new Date(),
    sshConfig,
    status: 'running',
    machineIp: sshConfig.sshHost,
    instanceKey
  };

  runningDataCollection.set(instanceKey, instance);
  saveDataCollectionInstances();
  return instance;
}

// Function to remove a running data collection instance
function removeDataCollectionInstance(sshHost) {
  runningDataCollection.delete(sshHost);
  saveDataCollectionInstances();
}

// Function to get all running data collection instances
function getDataCollectionInstances() {
  return Array.from(runningDataCollection.values());
}

// Function to check if a machine already has a running data collection instance
function isDataCollectionRunning(sshHost) {
  return runningDataCollection.has(sshHost);
}

// Function to verify all running data collection instances
async function verifyAllDataCollectionInstances() {
  const instancesToRemove = [];
  
  for (const [key, instance] of runningDataCollection.entries()) {
    try {
      const isRunning = await verifyProcess(instance.sshConfig, instance.pid);
      if (!isRunning) {
        instancesToRemove.push(key);
      }
    } catch (error) {
      console.error(`Error verifying data collection instance ${key}:`, error);
      instancesToRemove.push(key);
    }
  }

  // Remove stopped instances
  for (const key of instancesToRemove) {
    runningDataCollection.delete(key);
  }

  if (instancesToRemove.length > 0) {
    saveDataCollectionInstances();
  }

  return instancesToRemove.length > 0;
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
  
  // Send initial connection message with auto-clear
  ws.send(JSON.stringify({
    type: 'log',
    content: 'Successfully connected to the data collection machine!',
    autoClear: true  // Add flag to indicate this message should auto-clear
  }));
  
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
              content: chunk.toString(),
              autoClear: false  // Regular log messages don't auto-clear
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
      readyTimeout: 60000, // Increase timeout to 60 seconds
      keepaliveInterval: 10000,
      keepaliveCountMax: 10,
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
    res.json({ 
      message: 'Connection successful',
      autoClear: true  // Add flag to indicate this message should auto-clear
    });
  } catch (error) {
    console.error('SSH Test Error:', error);
    res.status(500).json({ 
      error: 'Failed to connect to the data collection machine',
      autoClear: true  // Add flag to indicate this message should auto-clear
    });
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

// Add verification endpoint
app.get('/api/traffic-generator/verify-instances', async (req, res) => {
  try {
    const hasChanges = await verifyAllInstances();
    const instances = getRunningInstances();
    res.json({ 
      instances,
      hasChanges
    });
  } catch (error) {
    console.error('Error verifying instances:', error);
    res.status(500).json({ 
      error: 'Failed to verify instances',
      details: error.message
    });
  }
});

// Data Collection endpoint
app.post('/api/data-collection/run', async (req, res) => {
  let ssh = null;
  try {
    const { mongodbUsername, mongodbPassword, mongodbHost, mongodbDatabase, mongodbCollection, autoRestart, ...sshConfig } = req.body;
    
    // Check if this machine already has a running instance
    if (isDataCollectionRunning(sshConfig.sshHost)) {
      return res.status(400).json({
        error: 'Machine already has a running data collection instance',
        details: `Machine ${sshConfig.sshHost} already has a data collection instance running`
      });
    }

    ssh = await createSSHConnection(sshConfig);
    
    // Create a unique log file name
    const timestamp = new Date().getTime();
    const logFileName = `data_collection_${timestamp}.log`;
    const logFilePath = path.join(logsDir, logFileName);
    const remoteLogFile = `/tmp/${logFileName}`;
    
    // Create empty log file first
    await ssh.execCommand(`touch ${remoteLogFile}`);

    // Install required packages in smaller steps
    const installSteps = [
      // Step 0: Check and remove apt locks
      `sudo rm /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*`,
      
      // Step 1: Update system
      `sudo apt update && sudo apt upgrade -y`,
      
      // Step 2: Install system packages
      `sudo apt install -y tcpdump tshark sysstat ifstat dstat vnstat snmpd python3-pip`,
      
      // Step 5: Install Python packages
      `pip3 install scapy pandas numpy psutil websockets asyncio pymongo python-dotenv`,
      
      // Step 6: Start services
      `sudo systemctl enable --now sysstat && sudo systemctl enable --now snmpd`
    ];

    console.log('Installing required packages...');
    for (const step of installSteps) {
      try {
        console.log(`Executing step: ${step}`);
        // Add retry logic for apt commands
        let retries = 3;
        let lastError = null;
        
        while (retries > 0) {
          try {
            const result = await ssh.execCommand(step);
            console.log(`Command output: ${result.stdout}`);
            if (result.stderr) {
              console.log(`Command errors: ${result.stderr}`);
            }
            
            if (result.code !== 0) {
              console.warn(`Warning: Step completed with non-zero exit code: ${result.stderr || result.stdout}`);
              if (result.stderr && result.stderr.includes('Could not get lock')) {
                // If it's a lock error, wait and retry
                console.log('Lock error detected, waiting 5 seconds before retry...');
                await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
                retries--;
                continue;
              }
            }
            console.log(`Step completed successfully: ${result.stdout}`);
            break; // Success, exit retry loop
          } catch (error) {
            lastError = error;
            console.error(`Attempt failed: ${error.message}`);
            if (error.message && error.message.includes('Could not get lock')) {
              console.log('Lock error detected, waiting 5 seconds before retry...');
              await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
              retries--;
              continue;
            }
            throw error; // If it's not a lock error, throw immediately
          }
        }
        
        if (retries === 0 && lastError) {
          throw lastError;
        }
      } catch (error) {
        console.error(`Error executing step: ${error.message}`);
        // Continue with next step even if this one fails
      }
    }

    // Create/update .env file in the dataprox directory
    const envCommand = `cd ~/dataprox && bash -c '
      # Create/update .env file with the form data
      cat > .env << EOL
# MongoDB Configuration
MONGODB_USERNAME=${mongodbUsername || ''}
MONGODB_PASSWORD=${mongodbPassword || ''}
MONGODB_HOST=${mongodbHost}
MONGODB_DATABASE=${mongodbDatabase}
MONGODB_COLLECTION=${mongodbCollection}
AUTO_RESTART=${autoRestart}

# Connection string will be constructed in the script based on these values
EOL

      # Display .env file contents for verification
      echo "Created .env file with contents:"
      cat .env
    '`;

    console.log('Creating .env file...');
    const envResult = await ssh.execCommand(envCommand);
    console.log('ENV file creation result:', envResult);

    // First, test MongoDB connection with more detailed error handling
    const mongoTestCommand = `python3 -c "
import sys
from pymongo import MongoClient
try:
    print('Attempting to connect to MongoDB...')
    
    # Get environment variables
    mongodb_host = '${mongodbHost}'
    mongodb_database = '${mongodbDatabase}'
    mongodb_username = '${mongodbUsername}'
    mongodb_password = '${mongodbPassword}'
    
    # Construct connection string based on provided credentials
    if mongodb_username and mongodb_password:
        # With authentication
        conn_str = f'mongodb://{mongodb_username}:{mongodb_password}@{mongodb_host}/{mongodb_database}'
    else:
        # Without authentication
        conn_str = f'mongodb://{mongodb_host}/{mongodb_database}'
    
    print(f'Connection string: {conn_str}')
    
    # Try connection with a timeout
    client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
    
    # Force a connection to verify it works
    client.server_info()
    print('MongoDB connection successful')
    
    # Test database access
    db = client[mongodb_database]
    collections = db.list_collection_names()
    print(f'Available collections: {collections}')
    
    # Test collection access
    collection = db['${mongodbCollection}']
    count = collection.count_documents({})
    print(f'Number of documents in collection: {count}')
    
    sys.exit(0)
except Exception as e:
    print(f'MongoDB connection failed with error: {str(e)}')
    print(f'Error type: {type(e).__name__}')
    sys.exit(1)
"`;

    console.log('Testing MongoDB connection...');
    const mongoTestResult = await ssh.execCommand(mongoTestCommand);
    console.log('MongoDB test result:', mongoTestResult);
    
    if (mongoTestResult.code !== 0) {
      throw new Error(`MongoDB connection test failed: ${mongoTestResult.stderr || mongoTestResult.stdout}`);
    }

    // Run the data collection script with error handling
    const command = `cd ~/dataprox/TrafficLogger && bash -c '
      timestamp=$(date +%s)
      pidfile="/tmp/data_collection_${timestamp}.pid"
      logfile="${remoteLogFile}"

      # Log the parameters being passed
      echo "Starting data collection with parameters:" > "$logfile"
      echo "MongoDB Username: ${mongodbUsername}" >> "$logfile"
      echo "MongoDB Host: ${mongodbHost}" >> "$logfile"
      echo "MongoDB Database: ${mongodbDatabase}" >> "$logfile"
      echo "MongoDB Collection: ${mongodbCollection}" >> "$logfile"
      echo "Auto Restart: ${autoRestart}" >> "$logfile"
      echo "----------------------------------------" >> "$logfile"

      # Start the data collection with nohup and in background
      nohup python3 collect_features.py > "$logfile" 2>&1 &
      echo $! > "$pidfile"

      # Wait a few seconds and check if the process is still running
      sleep 5
      if ! ps -p $(cat "$pidfile") > /dev/null; then
        echo "Process failed to start. Check the log file for details."
        exit 1
      fi
    '`;

    const result = await ssh.execCommand(command);
    
    if (result.code !== 0) {
      // Read the log file to get the error details
      const logContent = await ssh.execCommand(`cat ${remoteLogFile}`);
      throw new Error(`Failed to start data collection: ${logContent.stdout || logContent.stderr || result.stderr}`);
    }
    
    // Get the PID
    const pidResult = await ssh.execCommand(`cat /tmp/data_collection_${timestamp}.pid`);
    const pid = pidResult.stdout.trim();

    // Verify the process is running
    const checkProcess = await ssh.execCommand(`ps -p ${pid} | grep -v TTY`);
    if (checkProcess.stdout.trim().length === 0) {
      // Read the log file to get the error details
      const logContent = await ssh.execCommand(`cat ${remoteLogFile}`);
      throw new Error(`Process failed to start: ${logContent.stdout || logContent.stderr}`);
    }

    // Add to running instances
    const instance = addDataCollectionInstance(pid, sshConfig);

    res.json({ 
      message: 'Data collection started successfully',
      details: {
        stdout: result.stdout,
        stderr: result.stderr,
        pid: pid,
        logFile: `/api/logs/${logFileName}`,
        instance: instance
      }
    });
  } catch (error) {
    console.error('Data Collection Error:', error);
    if (ssh) {
      ssh.dispose();
    }
    res.status(500).json({ 
      error: 'Failed to start data collection',
      details: error.message
    });
  }
});

// Get running data collection instances endpoint
app.get('/api/data-collection/instances', (req, res) => {
  try {
    const instances = getDataCollectionInstances();
    res.json({ instances });
  } catch (error) {
    console.error('Error getting running data collection instances:', error);
    res.status(500).json({ error: 'Failed to get running data collection instances' });
  }
});

// Stop data collection endpoint
app.post('/api/data-collection/stop', async (req, res) => {
  let ssh = null;
  try {
    const { pid, sshHost, sshUsername, sshPassword, sshKeyPath } = req.body;
    
    // Validate required SSH credentials
    if (!sshHost || !sshUsername || (!sshPassword && !sshKeyPath)) {
      return res.status(400).json({
        error: 'Missing required SSH credentials',
        details: 'SSH host, username, and either password or key path are required to stop processes'
      });
    }

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
        removeDataCollectionInstance(sshHost);
        return res.json({ 
          message: 'Process was not running, removed from tracking',
          stoppedPid: pid
        });
      }
    }
    
    if (pid) {
      // Stop specific process by PID
      try {
        await ssh.execCommand(`kill -9 ${pid}`);
      } catch (error) {
        console.error('Error stopping process:', error);
        // Even if there's an error, remove from tracking
        removeDataCollectionInstance(sshHost);
      }
    } else {
      // Kill all data collection processes
      try {
        // First try to kill by PID if provided
        if (pid) {
          await ssh.execCommand(`kill -9 ${pid}`);
        }
        
        // Then kill any remaining collect_features.py processes
        await ssh.execCommand('pkill -9 -f collect_features.py');
        
        // Also kill any Python processes that might be running the script
        await ssh.execCommand('pkill -f collect_features.py');
        // Clear all running instances for this machine
        removeDataCollectionInstance(sshHost);
      } catch (error) {
        console.error('Error stopping all processes:', error);
        // Even if there's an error, remove from tracking
        removeDataCollectionInstance(sshHost);
      }
    }
    
    ssh.dispose();
    res.json({ 
      message: 'Data collection stopped successfully',
      stoppedPid: pid || 'all'
    });
  } catch (error) {
    console.error('Stop Data Collection Error:', error);
    if (ssh) {
      ssh.dispose();
    }
    // Even if there's an error, try to remove from tracking
    if (req.body.sshHost) {
      removeDataCollectionInstance(req.body.sshHost);
    }
    res.status(500).json({ 
      error: 'Failed to stop data collection',
      details: error.message
    });
  }
});

// Add verification endpoint for data collection
app.get('/api/data-collection/verify-instances', async (req, res) => {
  try {
    const hasChanges = await verifyAllDataCollectionInstances();
    const instances = getDataCollectionInstances();
    res.json({ 
      instances,
      hasChanges
    });
  } catch (error) {
    console.error('Error verifying data collection instances:', error);
    res.status(500).json({ 
      error: 'Failed to verify data collection instances',
      details: error.message
    });
  }
});

// Initialize server
Promise.all([
  loadRunningInstances(),
  loadDataCollectionInstances()
]).then(() => {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});