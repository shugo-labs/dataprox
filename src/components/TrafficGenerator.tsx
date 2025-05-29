import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Alert,
  CircularProgress,
  Grid,
  Divider,
  Stack,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import axios from 'axios';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';

interface TrafficGeneratorProps {}

interface LogFile {
  name: string;
  size: number;
  created: string;
}

interface RunningInstance {
  nodeIndex: number;
  pid: string;
  startTime: string;
  status: string;
  machineIp: string;
  moatPublicIp: string;
  instanceKey: string;
  totalDuration: number;
}

const TrafficGenerator: React.FC<TrafficGeneratorProps> = () => {
  const [formData, setFormData] = useState({
    // SSH Configuration
    sshHost: '',
    sshUsername: '',
    sshPassword: '',
    sshKeyPath: '',
    // Traffic Generator Configuration
    interface: '',
    moatPrivateIp: '',
    moatPublicIp: '',
    privateIp: '',
    nodeIndex: '',
    totalDuration: '',
  });
  const [loading, setLoading] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string | null>(null);
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [selectedLogFile, setSelectedLogFile] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [wsConnected, setWsConnected] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [runningInstances, setRunningInstances] = useState<RunningInstance[]>([]);

  useEffect(() => {
    // Fetch log files when component mounts
    fetchLogFiles();

    // Set up auto-refresh interval
    const interval = setInterval(() => {
      fetchLogFiles();
    }, 5000);

    return () => {
      clearInterval(interval);
      if (ws) {
        ws.close();
      }
    };
  }, [ws]);

  // Add effect for fetching and verifying running instances
  useEffect(() => {
    const fetchInstances = async () => {
      try {
        const response = await fetch('/api/traffic-generator/verify-instances');
        const data = await response.json();
        if (data.instances) {
          console.log('Received instances:', data.instances); // Debug log
          setRunningInstances(data.instances);
          // If instances were removed, show a message
          if (data.hasChanges) {
            setSuccess('Running instances updated');
          }
        }
      } catch (error) {
        console.error('Error fetching running instances:', error);
      }
    };

    // Fetch immediately and then every 5 seconds
    fetchInstances();
    const interval = setInterval(fetchInstances, 5000);

    return () => clearInterval(interval);
  }, []);

  // Add effect for auto-clearing success messages
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => {
        setSuccess(null);
      }, 5000); // Clear after 5 seconds
      return () => clearTimeout(timer);
    }
  }, [success]);

  // Add effect for auto-clearing connection status
  useEffect(() => {
    if (connectionStatus) {
      const timer = setTimeout(() => {
        setConnectionStatus(null);
      }, 5000); // Clear after 5 seconds
      return () => clearTimeout(timer);
    }
  }, [connectionStatus]);

  const fetchLogFiles = async () => {
    try {
      const response = await axios.get('/api/logs');
      if (Array.isArray(response.data)) {
        setLogFiles(response.data);
      } else {
        console.error('Invalid response format:', response.data);
        setLogFiles([]);
      }
    } catch (err) {
      console.error('Error fetching log files:', err);
      setLogFiles([]);
    }
  };

  const handleLogFileSelect = async (fileName: string) => {
    setSelectedLogFile(fileName);
    setLogContent('');

    // Close existing WebSocket connection if any
    if (ws) {
      ws.close();
    }

    // Create new WebSocket connection
    const newWs = new WebSocket('ws://localhost:3002');
    setWs(newWs);

    newWs.onopen = () => {
      setWsConnected(true);
      newWs.send(JSON.stringify({
        type: 'subscribe',
        logFile: fileName
      }));
    };

    newWs.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'log') {
        setLogContent(prev => prev + data.content);
      }
    };

    newWs.onclose = () => {
      setWsConnected(false);
    };

    // Fetch initial log content
    try {
      const response = await axios.get(`/api/logs/${fileName}`);
      setLogContent(response.data.content);
    } catch (err) {
      console.error('Error fetching log content:', err);
    }
  };

  const handleDeleteLog = async (fileName: string) => {
    try {
      await axios.delete(`/api/traffic-generator/logs/${fileName}`);
      fetchLogFiles();
      if (selectedLogFile === fileName) {
        setSelectedLogFile(null);
        setLogContent('');
        if (ws) {
          ws.close();
        }
      }
    } catch (err) {
      console.error('Error deleting log file:', err);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const testConnection = async () => {
    setLoading(true);
    setError(null);
    setConnectionStatus(null);

    try {
      const response = await axios.post('/api/traffic-generator/test-connection', {
        sshHost: formData.sshHost,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
      });
      setConnectionStatus('Successfully connected to the traffic generator machine!');
    } catch (err) {
      setError('Failed to connect to the traffic generator machine. Please check your SSH credentials.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStopInstance = async (pid: string, nodeIndex: number, machineIp: string) => {
    // Check if we have the required SSH credentials
    if (!formData.sshUsername || (!formData.sshPassword && !formData.sshKeyPath)) {
      setError('SSH credentials are required to stop the instance. Please provide SSH username and either password or key path.');
      return;
    }

    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await axios.post('/api/traffic-generator/stop', {
        sshHost: machineIp,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
        commands: [
          `pkill -P ${pid}`,  // Kill all child processes of the run_traffic.sh
          `kill ${pid}`       // Kill the run_traffic.sh process itself
        ]
      });

      setSuccess(`Traffic generator instance ${nodeIndex} stopped successfully!`);
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/traffic-generator/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to stop traffic generator instance. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  const handleStop = async () => {
    // Check if we have the required SSH credentials
    if (!formData.sshHost || !formData.sshUsername || (!formData.sshPassword && !formData.sshKeyPath)) {
      setError('SSH credentials are required to stop the instance. Please provide SSH host, username and either password or key path.');
      return;
    }

    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      // Stop all traffic processes for the current machine
      const stopResponse = await axios.post('/api/traffic-generator/stop', {
        sshHost: formData.sshHost,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
        commands: [
          '/usr/bin/pkill -f "run_traffic.sh"',
          '/usr/bin/pkill -f "python3"'
        ]
      });

      setSuccess('All traffic processes stopped successfully!');
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/traffic-generator/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to stop traffic processes. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Check if node index is already in use for the same receiver IP
    const nodeIndexNum = parseInt(formData.nodeIndex);
    const durationNum = parseInt(formData.totalDuration);
    
    if (runningInstances.some(instance => 
      parseInt(instance.nodeIndex.toString()) === nodeIndexNum && 
      instance.moatPublicIp === formData.moatPublicIp
    )) {
      setError(`Node index ${nodeIndexNum} is already in use for receiver IP ${formData.moatPublicIp}. Please choose a different node index.`);
      return;
    }

    // Check if this machine already has a running instance
    if (runningInstances.some(instance => instance.machineIp === formData.sshHost)) {
      setError(`Machine ${formData.sshHost} already has a running instance. Only one instance per machine is allowed.`);
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      // Ensure totalDuration is sent as a number
      const submitData = {
        ...formData,
        totalDuration: durationNum
      };
      
      console.log('Submitting form data:', submitData);
      const response = await axios.post('/api/traffic-generator/run', submitData);
      console.log('Run response:', response.data);
      
      setSuccess('Traffic generation started successfully!');
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/traffic-generator/instances');
      const instancesData = await instancesResponse.json();
      console.log('Fetched instances:', instancesData);
      
      // Ensure duration is a number in the instances data
      const processedInstances = instancesData.instances.map((instance: any) => ({
        ...instance,
        totalDuration: durationNum // Use the duration from the form
      }));
      
      setRunningInstances(processedInstances);
      
      // Reset form data after successful submission
      setFormData({
        sshHost: '',
        sshUsername: '',
        sshPassword: '',
        sshKeyPath: '',
        interface: '',
        moatPrivateIp: '',
        moatPublicIp: '',
        privateIp: '',
        nodeIndex: '',
        totalDuration: '',
      });
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to start traffic generation. Please try again.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ maxWidth: 800, mx: 'auto' }}>
      {/* <Typography variant="h5" gutterBottom>
        Traffic Generator Configuration
      </Typography> */}

      {/* Running Instances Section */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540', userSelect: 'none' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            Running Instances ({runningInstances.length})
          </Typography>
        </Box>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Machine IP</TableCell>
                <TableCell>Node Index</TableCell>
                <TableCell>PID</TableCell>
                <TableCell>Start Time</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Moat IP</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {runningInstances.length > 0 ? (
                runningInstances.map((instance) => (
                  <TableRow key={instance.instanceKey}>
                    <TableCell>{instance.machineIp}</TableCell>
                    <TableCell>{instance.nodeIndex}</TableCell>
                    <TableCell>{instance.pid}</TableCell>
                    <TableCell>{new Date(instance.startTime).toLocaleString()}</TableCell>
                    <TableCell>{instance.totalDuration || 0}s</TableCell>
                    <TableCell>{instance.moatPublicIp}</TableCell>
                    <TableCell>
                      <Button
                        variant="contained"
                        color="error"
                        size="small"
                        onClick={() => handleStopInstance(instance.pid, instance.nodeIndex, instance.machineIp)}
                        disabled={stopping}
                      >
                        {stopping ? <CircularProgress size={20} /> : 'Stop'}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    No running instances
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {connectionStatus && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {connectionStatus}
        </Alert>
      )}

      <Typography variant="h6" sx={{ mt: 3, mb: 2, userSelect: 'none' }}>
        SSH Connection
      </Typography>
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540', userSelect: 'none' }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="SSH Host"
              name="sshHost"
              value={formData.sshHost}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="SSH Username"
              name="sshUsername"
              value={formData.sshUsername}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="SSH Password"
              name="sshPassword"
              type="password"
              value={formData.sshPassword}
              onChange={handleInputChange}
              helperText="Password if using pwd authentication"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="SSH Key Path"
              name="sshKeyPath"
              value={formData.sshKeyPath}
              onChange={handleInputChange}
              helperText="Path to private key file if using key-based authentication"
            />
          </Grid>
        </Grid>
      </Paper>

      <Button
        variant="outlined"
        color="primary"
        onClick={testConnection}
        disabled={loading || stopping}
        sx={{ 
          mt: 2,
          borderColor: '#03FFF6',
          color: '#03FFF6',
          '&:hover': {
            borderColor: '#03FFF6',
            backgroundColor: 'rgba(3, 255, 246, 0.1)'
          },
          '&.Mui-disabled': {
            borderColor: 'rgba(255, 255, 255, 0.12)',
            color: 'rgba(255, 255, 255, 0.12)'
          }
        }}
      >
        Test Connection
      </Button>

      <Divider sx={{ my: 4 }} />

      <Typography variant="h6" sx={{ mb: 2, userSelect: 'none' }}>
        Parameters
      </Typography>
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540', userSelect: 'none' }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Interface"
              name="interface"
              value={formData.interface}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Moat Private IP"
              name="moatPrivateIp"
              value={formData.moatPrivateIp}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Moat Public IP"
              name="moatPublicIp"
              value={formData.moatPublicIp}
              onChange={handleInputChange}
              required
              helperText="Public IP of the receiver machine"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Tgen Private IP"
              name="privateIp"
              value={formData.privateIp}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Node Index"
              name="nodeIndex"
              value={formData.nodeIndex}
              onChange={handleInputChange}
              required
              type="number"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Total Duration (seconds)"
              name="totalDuration"
              value={formData.totalDuration}
              onChange={handleInputChange}
              required
              type="number"
            />
          </Grid>
        </Grid>
      </Paper>

      <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
        <Button
          type="submit"
          variant="contained"
          fullWidth
          disabled={loading || stopping || 
            !formData.sshHost || 
            !formData.sshUsername || 
            !formData.interface || 
            !formData.moatPrivateIp || 
            !formData.moatPublicIp || 
            !formData.privateIp || 
            !formData.nodeIndex || 
            !formData.totalDuration
          }
          sx={{
            background: 'linear-gradient(45deg, #00FF9D 0%, #00FF9D 40%, #03FFF6 60%, #00B8FF 100%)',
            color: '#1B1B3A',
            fontWeight: 600,
            border: 'none',
            '&:hover': {
              background: 'linear-gradient(45deg, #00FF9D 0%, #00FF9D 40%, #03FFF6 60%, #00B8FF 100%)',
              opacity: 0.9,
              border: 'none'
            },
            '&.Mui-disabled': {
              background: 'none',
              backgroundColor: 'rgba(255, 255, 255, 0.12)',
              border: 'none'
            }
          }}
        >
          {loading ? <CircularProgress size={24} /> : 'Start Traffic Generation'}
        </Button>
        <Button
          variant="contained"
          color="error"
          fullWidth
          onClick={handleStop}
          disabled={stopping || runningInstances.length === 0}
        >
          {stopping ? <CircularProgress size={24} /> : 'Stop All'}
        </Button>
      </Box>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6" sx={{ userSelect: 'none' }}>
          Log Files
        </Typography>
      </Box>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <List sx={{ 
            bgcolor: 'background.paper', 
            borderRadius: 1,
            height: '400px',
            overflow: 'auto'
          }}>
            {logFiles.map((file) => (
              <ListItem
                key={file.name}
                secondaryAction={
                  <IconButton
                    edge="end"
                    aria-label="delete"
                    onClick={() => handleDeleteLog(file.name)}
                    sx={{ cursor: 'pointer' }}
                  >
                    <DeleteIcon />
                  </IconButton>
                }
                selected={selectedLogFile === file.name}
                onClick={() => handleLogFileSelect(file.name)}
                sx={{
                  cursor: 'pointer',
                  '&:hover': {
                    bgcolor: 'action.hover',
                  },
                  display: 'flex',
                  alignItems: 'center',
                  width: '100%',
                  '& .MuiListItemText-root': {
                    flex: '1 1 auto'
                  }
                }}
              >
                <ListItemText
                  primary={file.name}
                  secondary={`${(file.size / 1024).toFixed(2)} KB - ${new Date(file.created).toLocaleString()}`}
                  sx={{ cursor: 'pointer' }}
                />
              </ListItem>
            ))}
          </List>
        </Grid>
        <Grid item xs={12} md={8}>
          <Box
            sx={{
              bgcolor: 'background.paper',
              borderRadius: 1,
              p: 2,
              height: '400px',
              overflow: 'auto',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            {selectedLogFile ? (
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', flex: 1 }}>
                {logContent || 'Loading log content...'}
              </pre>
            ) : (
              <Typography color="text.secondary" sx={{ textAlign: 'center', mt: 2, userSelect: 'none' }}>
                Select a log file to view its contents
              </Typography>
            )}
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default TrafficGenerator;