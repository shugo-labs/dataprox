import React, { useState, useEffect, useRef } from 'react';
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
  moatPrivateIp: string;
  privateIp: string;
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
    nodeIndex: '0',
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
  const logContentRef = useRef<HTMLPreElement>(null);
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

  // Add effect for auto-refreshing log content
  useEffect(() => {
    let interval: NodeJS.Timeout;

    const fetchLogContent = async () => {
      if (selectedLogFile) {
        try {
          const response = await axios.get(`/api/logs/${selectedLogFile}`);
          setLogContent(response.data.content);
        } catch (err) {
          console.error('Error fetching log content:', err);
        }
      }
    };

    // Start polling immediately if there's a selected file
    if (selectedLogFile) {
      fetchLogContent();
      // Poll every 500ms for more frequent updates
      interval = setInterval(fetchLogContent, 500);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [selectedLogFile]);

  // Add effect for immediate scrolling when content changes
  useEffect(() => {
    if (logContentRef.current) {
      logContentRef.current.scrollTop = logContentRef.current.scrollHeight;
    }
  }, [logContent]);

  const fetchLogFiles = async () => {
    try {
      const response = await axios.get('/api/logs');
      if (Array.isArray(response.data)) {
        const sortedFiles = response.data.sort((a, b) => 
          new Date(b.created).getTime() - new Date(a.created).getTime()
        );
        setLogFiles(sortedFiles);
        
        // Select the most recent file if none is selected
        if (sortedFiles.length > 0 && !selectedLogFile) {
          handleLogFileSelect(sortedFiles[0].name);
        }
      } else {
        console.error('Invalid response format:', response.data);
        setLogFiles([]);
      }
    } catch (err) {
      console.error('Error fetching log files:', err);
      setLogFiles([]);
    }
  };

  const handleLogFileSelect = (fileName: string) => {
    setSelectedLogFile(fileName);
    setLogContent('');
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
    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await axios.post('/api/traffic-generator/stop', {
        pid,
        sshHost: machineIp,
        nodeIndex
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
    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      // Stop all traffic processes for the current machine
      const stopResponse = await axios.post('/api/traffic-generator/stop', {
        sshHost: formData.sshHost
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
    
    // Check if this machine already has a running instance
    if (runningInstances.some(instance => instance.machineIp === formData.sshHost)) {
      setError(`Machine ${formData.sshHost} already has a running instance. Only one instance per machine is allowed.`);
      return;
    }

    // Check if there's already an instance running towards this moat public IP
    if (runningInstances.some(instance => instance.moatPublicIp === formData.moatPublicIp)) {
      setError(`There is already a traffic generator instance running towards moat IP ${formData.moatPublicIp}. Only one instance per moat is allowed.`);
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      // Ensure totalDuration is sent as a number
      const submitData = {
        ...formData,
        totalDuration: parseInt(formData.totalDuration)
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
        totalDuration: parseInt(formData.totalDuration) // Use the duration from the form
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
        nodeIndex: '0',  // Reset to '0'
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
                <TableCell sx={{ userSelect: 'none' }}>Tgen Public IP</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Tgen Private IP</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>PID</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Start Time</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Moat Public IP</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Moat Private IP</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {runningInstances.length > 0 ? (
                runningInstances.map((instance) => (
                  <TableRow key={instance.instanceKey}>
                    <TableCell>{instance.machineIp}</TableCell>
                    <TableCell>{instance.privateIp}</TableCell>
                    <TableCell>{instance.pid}</TableCell>
                    <TableCell>{new Date(instance.startTime).toLocaleString()}</TableCell>
                    <TableCell>{instance.moatPublicIp}</TableCell>
                    <TableCell>{instance.moatPrivateIp}</TableCell>
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
        Traffic Generator Configuration
      </Typography>
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540' }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Network Interface"
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
              label="Total Duration (seconds)"
              name="totalDuration"
              type="number"
              value={formData.totalDuration}
              onChange={handleInputChange}
              required
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
            {logFiles
              .sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime())
              .map((file) => (
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
              <pre 
                ref={logContentRef}
                style={{ 
                  margin: 0, 
                  whiteSpace: 'pre-wrap', 
                  flex: 1,
                  overflow: 'auto'
                }}
              >
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