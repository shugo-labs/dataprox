const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const fs = require('fs');
const WebSocket = require('ws');
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
const server = require('http').createServer(app);

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
      .map(file => ({
        name: file,
        path: `/api/logs/${file}`,
        size: fs.statSync(path.join(logsDir, file)).size,
        created: fs.statSync(path.join(logsDir, file)).birthtime
      }));
    res.json(files);
  } catch (error) {
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

// Stop traffic processes endpoint
app.post('/api/traffic-generator/stop', async (req, res) => {
  try {
    const { ...sshConfig } = req.body;
    const ssh = await createSSHConnection(sshConfig);

    // Kill any running traffic processes
    const commands = [
      "pkill -f 'run_traffic.sh'",  // Kill the main script
      "pkill -f 'traffic_generator'", // Kill the traffic generator process
      "pkill -f 'tcpdump'", // Kill any tcpdump processes
      "pkill -f 'iperf'", // Kill any iperf processes
    ];

    for (const cmd of commands) {
      try {
        await ssh.execCommand(cmd);
      } catch (error) {
        // Ignore errors if process is not found
        console.log(`Command ${cmd} returned:`, error.message);
      }
    }

    ssh.dispose();
    res.json({ message: 'Traffic processes stopped successfully' });
  } catch (error) {
    console.error('Stop Traffic Error:', error);
    res.status(500).json({ 
      error: 'Failed to stop traffic processes',
      details: error.message 
    });
  }
});

// Traffic Generator endpoint
app.post('/api/traffic-generator/run', async (req, res) => {
  let ssh = null;
  try {
    const { interface, moatPrivateIp, privateIp, nodeIndex, totalDuration, ...sshConfig } = req.body;
    
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
    await ssh.execCommand('chmod +x /home/borgg/dataprox/TrafficGenerator/run_traffic.sh');
    
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
    const command = `cd /home/borgg/dataprox/TrafficGenerator && bash -c '
      # Function to kill process group
      cleanup() {
        local pid=$1
        if [ -n "$pid" ]; then
          pkill -P $pid
          kill $pid 2>/dev/null
        fi
      }

      # Start the traffic generator script in a new process group
      setsid bash run_traffic.sh ${interface} ${moatPrivateIp} ${privateIp} ${nodeIndex} ${totalDuration} > ${remoteLogFile} 2>&1 &
      TRAFFIC_PID=$!
      echo $TRAFFIC_PID > /tmp/traffic_${timestamp}.pid

      # Wait for the specified duration
      sleep ${totalDuration}

      # Cleanup after duration
      cleanup $TRAFFIC_PID
    '`;
    
    // Execute the command
    const result = await ssh.execCommand(command);
    console.log('Script execution result:', result);

    // Get the PID
    const pidResult = await ssh.execCommand(`cat /tmp/traffic_${timestamp}.pid`);
    const pid = pidResult.stdout.trim();
    console.log('Process PID:', pid);

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
        logFile: `/api/logs/${logFileName}`
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

// Add cleanup endpoint
app.post('/api/traffic-generator/cleanup', async (req, res) => {
  try {
    const { pid, ...sshConfig } = req.body;
    const ssh = await createSSHConnection(sshConfig);
    
    // Kill the process and its children
    await ssh.execCommand(`pkill -P ${pid}`);
    await ssh.execCommand(`kill ${pid}`);
    
    ssh.dispose();
    res.json({ message: 'Cleanup completed successfully' });
  } catch (error) {
    console.error('Cleanup Error:', error);
    res.status(500).json({ error: 'Failed to cleanup processes' });
  }
});

// Data Collection endpoint
app.post('/api/data-collection/run', async (req, res) => {
  try {
    const { mongodbUsername, mongodbPassword, mongodbHost, mongodbDatabase, mongodbCollection, autoRestart, ...sshConfig } = req.body;
    
    const ssh = await createSSHConnection(sshConfig);
    
    // Clone repository if not exists
    await ssh.execCommand('if [ ! -d "TrafficLogger" ]; then git clone https://github.com/shugo-labs/dataprox.git; fi', {
      cwd: '/root'
    });
    
    // Create .env file
    const envContent = `MONGODB_USERNAME=${mongodbUsername}
MONGODB_PASSWORD=${mongodbPassword}
MONGODB_HOST=${mongodbHost}
MONGODB_DATABASE=${mongodbDatabase}
MONGODB_COLLECTION=${mongodbCollection}`;
    
    await ssh.execCommand(`echo '${envContent}' > /root/TrafficLogger/.env`);
    
    // Run the data collection script
    const command = `cd /root/TrafficLogger && ./run_data_collection.sh`;
    await ssh.execCommand(command);
    
    ssh.dispose();
    res.json({ message: 'Data collection started successfully' });
  } catch (error) {
    console.error('Data Collection Error:', error);
    res.status(500).json({ error: 'Failed to start data collection' });
  }
});

// The "catchall" handler: for any request that doesn't
// match one above, send back React's index.html file.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../build', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke!' });
});

// Start the server
server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
}); 