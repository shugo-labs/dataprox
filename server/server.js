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
        // Create SSH config from instance data
        const sshConfig = {
          sshHost: instance.machineIp,
          sshUsername: instance.sshUsername,
          sshPassword: instance.sshPassword,
          sshKeyPath: instance.sshKeyPath
        };

        const isRunning = await verifyProcess(sshConfig, instance.pid);
        if (isRunning) {
          // Ensure SSH config is included in the instance data
          instance.sshConfig = sshConfig;
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
function addRunningInstance(nodeIndex, pid, sshConfig, moatPublicIp, totalDuration) {
  const instanceKey = `${sshConfig.sshHost}-${nodeIndex}`;
  const instance = {
    nodeIndex: parseInt(nodeIndex),
    pid: pid,
    startTime: new Date().toISOString(),
    status: 'running',
    machineIp: sshConfig.sshHost,
    privateIp: sshConfig.privateIp,
    moatPublicIp: moatPublicIp,
    moatPrivateIp: sshConfig.moatPrivateIp,
    instanceKey: instanceKey,
    totalDuration: parseInt(totalDuration),
    // Store SSH config for verification
    sshConfig: sshConfig,
    sshUsername: sshConfig.sshUsername,
    sshPassword: sshConfig.sshPassword,
    sshKeyPath: sshConfig.sshKeyPath
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
function addDataCollectionInstance(pid, sshConfig, nodeIndex, tgenPublicIp) {
  const instanceKey = `${sshConfig.sshHost}-${nodeIndex}`; // Key for instance (one per machine per node)

  // Check if machine already has an instance for this node
  if (runningDataCollection.has(instanceKey)) {
    throw new Error(`Machine ${sshConfig.sshHost} already has a running data collection instance for node ${nodeIndex}`);
  }

  const instance = {
    pid,
    startTime: new Date(),
    sshConfig,
    status: 'running',
    machineIp: sshConfig.sshHost,
    nodeIndex: parseInt(nodeIndex),
    tgenPublicIp,
    tgenPrivateIp: sshConfig.mongodbTgenIp,
    moatPrivateIp: sshConfig.sshHostPrivateIp,
    instanceKey
  };

  runningDataCollection.set(instanceKey, instance);
  saveDataCollectionInstances();
  return instance;
}

// Function to remove a running data collection instance
function removeDataCollectionInstance(sshHost, nodeIndex) {
  const instanceKey = `${sshHost}-${nodeIndex}`;
  runningDataCollection.delete(instanceKey);
  saveDataCollectionInstances();
}

// Function to get all running data collection instances
function getDataCollectionInstances() {
  return Array.from(runningDataCollection.values());
}

// Function to check if a machine already has a running data collection instance for a specific node
function isDataCollectionRunning(sshHost, nodeIndex) {
  const instanceKey = `${sshHost}-${nodeIndex}`;
  return runningDataCollection.has(instanceKey);
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

// Add function to check and clone repository
async function ensureDataproxExists(ssh) {
  try {
    // Check if dataprox directory exists
    const checkDir = await ssh.execCommand('ls -la ~/dataprox');
    
    if (checkDir.code !== 0) {
      console.log('Cloning dataprox repository...');
      const cloneResult = await ssh.execCommand('git clone https://github.com/borgg-dev/dataprox.git ~/dataprox');
      if (cloneResult.code !== 0) {
        throw new Error(`Failed to clone repository: ${cloneResult.stderr}`);
      }
      console.log('Repository cloned successfully');
    } else {
      console.log('dataprox directory exists, pulling latest changes...');
      // Pull latest changes
      const pullResult = await ssh.execCommand('cd ~/dataprox && git pull');
      if (pullResult.code !== 0) {
        throw new Error(`Failed to pull latest changes: ${pullResult.stderr}`);
      }
      console.log('Latest changes pulled successfully');
    }
  } catch (error) {
    console.error('Error checking/cloning repository:', error);
    throw error;
  }
}

// Update Traffic Generator endpoint
app.post('/api/traffic-generator/run', async (req, res) => {
  let ssh = null;
  try {
    const { interface, moatPrivateIp, moatPublicIp, privateIp, nodeIndex, totalDuration, ...sshConfig } = req.body;
    
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
      moatPublicIp,
      privateIp,
      nodeIndex,
      totalDuration,
      sshHost: sshConfig.sshHost,
      sshUsername: sshConfig.sshUsername
    });

    ssh = await createSSHConnection(sshConfig);
    console.log('SSH connection established');
    
    // Ensure dataprox exists
    await ensureDataproxExists(ssh);
    
    // Make sure the script is executable
    console.log('Making script executable...');
    await ssh.execCommand('chmod +x ~/dataprox/TrafficGenerator/run_traffic.sh');
    
    // Create a unique log file name
    const timestamp = Date.now();
    const logFileName = `traffic_${timestamp}.log`;
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
        fs.appendFileSync(path.join(logsDir, logFileName), content);
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
        fs.appendFileSync(path.join(logsDir, logFileName), content);
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

      # Start the traffic generator in background but keep it in the same process group
      bash run_traffic.sh ${interface} ${moatPrivateIp} ${privateIp} ${nodeIndex} ${totalDuration} > "$logfile" 2>&1 &
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
    const instance = addRunningInstance(nodeIndex, pid, {
      ...sshConfig,
      privateIp: privateIp,
      moatPrivateIp: moatPrivateIp
    }, moatPublicIp, totalDuration);

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
    const { pid, nodeIndex, sshHost, cleanupFiles, cleanupAllFiles } = req.body;
    
    // Find the instance in our tracking
    const instance = Array.from(runningInstances.values()).find(
      inst => inst.machineIp === sshHost && (!pid || inst.pid === pid)
    );

    if (!instance) {
      return res.status(404).json({
        error: 'No running instance found',
        details: `No traffic generator instance is running on machine ${sshHost}`
      });
    }

    // Use stored SSH config from the instance
    const sshConfig = instance.sshConfig;

    // Test SSH connection before proceeding
    try {
      ssh = await createSSHConnection(sshConfig);
      console.log('SSH connection established for stop operation');
    } catch (error) {
      return res.status(401).json({
        error: 'Failed to establish SSH connection',
        details: 'Connection failed'
      });
    }

    if (pid) {
      // First get all child PIDs recursively
      const getAllChildPids = async (parentPid) => {
        const result = await ssh.execCommand(`ps --ppid ${parentPid} -o pid=`);
        const childPids = result.stdout.trim().split('\n').filter(Boolean);
        let allChildPids = [...childPids];
        
        // Recursively get children of children
        for (const childPid of childPids) {
          const grandChildPids = await getAllChildPids(childPid);
          allChildPids = [...allChildPids, ...grandChildPids];
        }
        
        return allChildPids;
      };

      // Get all child PIDs recursively
      const allChildPids = await getAllChildPids(pid);
      console.log('Found child PIDs:', allChildPids);
      
      // Kill all child processes first
      for (const childPid of allChildPids) {
        try {
          await ssh.execCommand(`kill -9 ${childPid}`);
        } catch (error) {
          console.error(`Error killing child process ${childPid}:`, error);
        }
      }
      
      // Then kill the parent process
      try {
        await ssh.execCommand(`kill -9 ${pid}`);
      } catch (error) {
        console.error(`Error killing parent process ${pid}:`, error);
      }
      
      // Verify all processes are stopped
      const checkResult = await ssh.execCommand(`ps -p ${pid},${allChildPids.join(',')} | grep -v TTY`);
      if (checkResult.stdout.trim().length === 0) {
        removeRunningInstance(nodeIndex, sshHost);
        
        // Cleanup files if requested
        if (cleanupFiles) {
          try {
            // Find and remove the PID file
            const pidFiles = await ssh.execCommand('ls /tmp/traffic_*.pid');
            const pidFileList = pidFiles.stdout.split('\n').filter(Boolean);
            for (const pidFile of pidFileList) {
              const filePid = await ssh.execCommand(`cat ${pidFile}`);
              if (filePid.stdout.trim() === pid) {
                // Remove both PID and log files
                await ssh.execCommand(`rm -f ${pidFile}`);
                await ssh.execCommand(`rm -f ${pidFile.replace('.pid', '.log')}`);
                break;
              }
            }
          } catch (err) {
            console.error('Error cleaning up files:', err);
          }
        }
      } else {
        // If any processes are still running, try pkill as a fallback
        await ssh.execCommand(`pkill -9 -P ${pid}`);
        // Also kill any remaining Python processes that might be related
        await ssh.execCommand(`pkill -9 -f traffic_generator_training.py`);
        removeRunningInstance(nodeIndex, sshHost);
      }
    } else {
      // Kill all traffic generator processes
      try {
        // First kill all run_traffic.sh processes and their children
        await ssh.execCommand('pkill -9 -f run_traffic.sh');
        // Then kill any remaining Python processes
        await ssh.execCommand('pkill -9 -f traffic_generator_training.py');
        // Clear all running instances for this machine
        for (const [key, instance] of runningInstances.entries()) {
          if (instance.machineIp === sshHost) {
            runningInstances.delete(key);
          }
        }
        saveRunningInstances();

        // Cleanup all files if requested
        if (cleanupAllFiles) {
          try {
            await ssh.execCommand('rm -f /tmp/traffic_*.pid /tmp/traffic_*.log /tmp/traffic_shaping.lock');
          } catch (err) {
            console.error('Error cleaning up all files:', err);
          }
        }
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
  try {
    // Get all running instances to check which PIDs are active
    const runningInstances = getRunningInstances();
    const activePids = new Set(runningInstances.map(instance => instance.pid));

    // Find all traffic PID files
    const pidFiles = await fs.readdir('/tmp');
    const trafficPidFiles = pidFiles.filter(file => file.startsWith('traffic_') && file.endsWith('.pid'));

    for (const pidFile of trafficPidFiles) {
      const pidFilePath = path.join('/tmp', pidFile);
      const logFile = pidFile.replace('.pid', '.log');
      const logFilePath = path.join('/tmp', logFile);

      try {
        // Read PID from file
        const pid = await fs.readFile(pidFilePath, 'utf8');
        
        // Check if process is running and not in active instances
        if (!activePids.has(pid.trim())) {
          // Remove both PID and log files
          await fs.unlink(pidFilePath);
          await fs.unlink(logFilePath).catch(() => {}); // Ignore if log file doesn't exist
        }
      } catch (err) {
        console.error(`Error processing ${pidFile}:`, err);
      }
    }

    // Remove traffic_shaping.lock if it exists
    const lockFile = path.join('/tmp', 'traffic_shaping.lock');
    try {
      await fs.unlink(lockFile);
    } catch (err) {
      // Ignore if file doesn't exist
    }

    res.json({ success: true, message: 'Cleanup completed successfully' });
  } catch (err) {
    console.error('Error during cleanup:', err);
    res.status(500).json({ 
      success: false, 
      details: 'Failed to cleanup traffic files',
      error: err.message 
    });
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

// Update Data Collection endpoint
app.post('/api/data-collection/run', async (req, res) => {
  let ssh = null;
  try {
    const { mongodbUri, mongodbDatabase, mongodbCollection, autoRestart, nodeIndex, tgenPublicIp, tgenPrivateIp, privateInterface, ...sshConfig } = req.body;
    
    // Check if this machine already has a running instance for this node
    if (isDataCollectionRunning(sshConfig.sshHost, nodeIndex)) {
      return res.status(400).json({
        error: 'Machine already has a running data collection instance for this node',
        details: `Machine ${sshConfig.sshHost} already has a data collection instance running for node ${nodeIndex}`
      });
    }

    ssh = await createSSHConnection(sshConfig);
    
    // Ensure dataprox exists
    await ensureDataproxExists(ssh);

    // Create a unique log file name
    const timestamp = new Date().getTime();
    const logFileName = `data_collection_${timestamp}.log`;
    const logFilePath = path.join(logsDir, logFileName);
    const remoteLogFile = `/tmp/${logFileName}`;
    
    // Create empty log file first
    await ssh.execCommand(`touch ${remoteLogFile}`);

    // Install required packages in smaller steps
    const installSteps = [
      // Step 0: Check and remove apt locks if they exist
      `for lock in /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*; do
        if [ -f "$lock" ]; then
          sudo rm "$lock"
        fi
      done`,
      
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
      const result = await ssh.execCommand(step);
      if (result.code !== 0) {
        console.error('Installation step failed:', step);
        console.error('Error:', result.stderr);
        throw new Error(`Failed to install required packages: ${result.stderr}`);
      }
    }

    // Create/update .env file in the dataprox directory
    const envCommand = `cd ~/dataprox && bash -c '
      # Create/update .env file with the form data
      cat > .env << EOL
# MongoDB Configuration
MONGODB_URI=${mongodbUri}
MONGODB_DATABASE=${mongodbDatabase}
MONGODB_COLLECTION=${mongodbCollection}
MONGODB_TGEN_IP=${tgenPrivateIp}
INTERFACE=${sshConfig.interface}
SSH_HOST_PRIVATE_IP=${sshConfig.sshHostPrivateIp}
AUTO_RESTART=${autoRestart}
NODE_INDEX=${nodeIndex}
EOL

      # Display .env file contents for verification
      echo "Created .env file with contents:"
      cat .env
    '`;

    console.log('Creating .env file...');
    const envResult = await ssh.execCommand(envCommand);
    console.log('ENV file creation result:', envResult);

    // Run setup_gre.py with sudo
    console.log('Setting up GRE tunnel...');
    const setupGreCommand = `cd ~/dataprox/TrafficLogger && sudo python3 setup_gre.py`;
    const setupGreResult = await ssh.execCommand(setupGreCommand);
    console.log('GRE setup result:', setupGreResult);

    if (setupGreResult.code !== 0) {
      throw new Error(`Failed to set up GRE tunnel: ${setupGreResult.stderr || setupGreResult.stdout}`);
    }

    // Test MongoDB connection with more detailed error handling
    const mongoTestCommand = `python3 -c "
import sys
from pymongo import MongoClient
try:
    print('Attempting to connect to MongoDB...')
    
    # Get environment variables
    mongodb_uri = '${mongodbUri}'
    mongodb_database = '${mongodbDatabase}'
    
    print(f'Connection string: {mongodb_uri}')
    
    # Try connection with a timeout
    client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
    
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
      echo "MongoDB URI: ${mongodbUri}" >> "$logfile"
      echo "MongoDB Database: ${mongodbDatabase}" >> "$logfile"
      echo "MongoDB Collection: ${mongodbCollection}" >> "$logfile"
      echo "Node Index: ${nodeIndex}" >> "$logfile"
      echo "Auto Restart: ${autoRestart}" >> "$logfile"
      echo "----------------------------------------" >> "$logfile"

      # Start the data collection with nohup and in background
      NODE_INDEX=${nodeIndex} nohup python3 collect_features.py > "$logfile" 2>&1 &
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
    const instance = addDataCollectionInstance(pid, { 
      ...sshConfig, 
      mongodbTgenIp: tgenPrivateIp,
      sshHostPrivateIp: sshConfig.sshHostPrivateIp 
    }, nodeIndex, tgenPublicIp);

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
    const { pid, sshHost, nodeIndex } = req.body;
    
    // Find the instance in our tracking
    const instance = Array.from(runningDataCollection.values()).find(
      inst => inst.machineIp === sshHost && 
             inst.nodeIndex === parseInt(nodeIndex) && 
             (!pid || inst.pid === pid)
    );

    if (!instance) {
      return res.status(404).json({
        error: 'No running instance found',
        details: `No data collection instance is running on machine ${sshHost} for node ${nodeIndex}`
      });
    }

    // Use stored SSH config from the instance
    const sshConfig = instance.sshConfig;

    // Test SSH connection before proceeding
    try {
      ssh = await createSSHConnection(sshConfig);
      console.log('SSH connection established for stop operation');
    } catch (error) {
      return res.status(401).json({
        error: 'Failed to establish SSH connection',
        details: 'Connection failed'
      });
    }

    if (pid) {
      // First get all child PIDs recursively
      const getAllChildPids = async (parentPid) => {
        const result = await ssh.execCommand(`ps --ppid ${parentPid} -o pid=`);
        const childPids = result.stdout.trim().split('\n').filter(Boolean);
        let allChildPids = [...childPids];
        
        // Recursively get children of children
        for (const childPid of childPids) {
          const grandChildPids = await getAllChildPids(childPid);
          allChildPids = [...allChildPids, ...grandChildPids];
        }
        
        return allChildPids;
      };

      // Get all child PIDs recursively
      const allChildPids = await getAllChildPids(pid);
      console.log('Found child PIDs:', allChildPids);
      
      // Kill all child processes first
      for (const childPid of allChildPids) {
        try {
          await ssh.execCommand(`kill -9 ${childPid}`);
        } catch (error) {
          console.error(`Error killing child process ${childPid}:`, error);
        }
      }
      
      // Then kill the parent process
      try {
        await ssh.execCommand(`kill -9 ${pid}`);
      } catch (error) {
        console.error(`Error killing parent process ${pid}:`, error);
      }
      
      // Verify all processes are stopped
      const checkResult = await ssh.execCommand(`ps -p ${pid},${allChildPids.join(',')} | grep -v TTY`);
      if (checkResult.stdout.trim().length === 0) {
        removeDataCollectionInstance(sshHost, nodeIndex);
      } else {
        // If any processes are still running, try pkill as a fallback
        await ssh.execCommand(`pkill -9 -P ${pid}`);
        // Also kill any remaining Python processes that might be related
        await ssh.execCommand(`pkill -9 -f collect_features.py`);
        removeDataCollectionInstance(sshHost, nodeIndex);
      }
    } else {
      // Kill all data collection processes for this node
      try {
        // First kill all collect_features.py processes and their children
        await ssh.execCommand(`pkill -9 -f "NODE_INDEX=${nodeIndex}.*collect_features.py"`);
        // Then kill any remaining Python processes for this node
        await ssh.execCommand(`pkill -9 -f "python3.*collect_features.py"`);
        // Remove from tracking
        removeDataCollectionInstance(sshHost, nodeIndex);
      } catch (error) {
        console.error('Error stopping all processes:', error);
        // Even if there's an error, remove from tracking
        removeDataCollectionInstance(sshHost, nodeIndex);
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
    if (req.body.sshHost && req.body.nodeIndex) {
      removeDataCollectionInstance(req.body.sshHost, req.body.nodeIndex);
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