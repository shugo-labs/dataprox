import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Alert,
  CircularProgress,
  FormControlLabel,
  Switch,
  Grid,
  Divider,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import axios from 'axios';

interface DataCollectionProps {}

interface RunningInstance {
  pid: string;
  startTime: string;
  status: string;
  machineIp: string;
  instanceKey: string;
  nodeIndex: number;
  moatPublicIp: string;
}

interface LogFile {
  name: string;
  size: number;
  created: string;
}

const DataCollection: React.FC<DataCollectionProps> = () => {
  const [formData, setFormData] = useState({
    // SSH Configuration
    sshHost: '',
    sshUsername: '',
    sshPassword: '',
    sshKeyPath: '',
    // MongoDB Configuration
    mongodbUri: '',
    mongodbDatabase: '',
    mongodbCollection: '',
    autoRestart: true,
    nodeIndex: '',
    moatPublicIp: '',
  });
  const [loading, setLoading] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string | null>(null);
  const [runningInstances, setRunningInstances] = useState<RunningInstance[]>([]);
  const [refreshing, setRefreshing] = useState(false);

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

  // Add effect for fetching and verifying running instances
  useEffect(() => {
    fetchRunningInstances();
    const interval = setInterval(fetchRunningInstances, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchRunningInstances = async () => {
    try {
      console.log('Fetching running instances...');
      const response = await fetch('/api/data-collection/instances');
      const data = await response.json();
      console.log('Received instances data:', data);
      if (data.instances) {
        setRunningInstances(data.instances);
      }
    } catch (error) {
      console.error('Error fetching running instances:', error);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const testConnection = async () => {
    setLoading(true);
    setError(null);
    setConnectionStatus(null);

    try {
      const response = await axios.post('/api/data-collection/test-connection', {
        sshHost: formData.sshHost,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
      });
      setConnectionStatus('Successfully connected to the data collection machine!');
    } catch (err) {
      setError('Failed to connect to the data collection machine. Please check your SSH credentials.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStopInstance = async (pid: string, machineIp: string) => {
    // Check if we have the required SSH credentials
    if (!formData.sshUsername || (!formData.sshPassword && !formData.sshKeyPath)) {
      setError('SSH credentials are required to stop the instance. Please provide SSH username and either password or key path.');
      return;
    }

    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await axios.post('/api/data-collection/stop', {
        pid,
        sshHost: machineIp,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
      });

      setSuccess('Data collection instance stopped successfully!');
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/data-collection/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to stop data collection instance. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  const handleStopAllInstances = async () => {
    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      // Stop all instances on all machines
      const stopPromises = runningInstances.map(instance => 
        axios.post('/api/data-collection/stop', {
          pid: instance.pid,
          sshHost: instance.machineIp,
          sshUsername: formData.sshUsername,
          sshPassword: formData.sshPassword,
          sshKeyPath: formData.sshKeyPath,
        })
      );

      await Promise.all(stopPromises);
      setSuccess('All data collection instances stopped successfully!');
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/data-collection/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to stop all data collection instances. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  const handleStopMachine = async (machineIp: string) => {
    // Check if we have the required SSH credentials
    if (!formData.sshUsername || (!formData.sshPassword && !formData.sshKeyPath)) {
      setError('SSH credentials are required to stop the instance. Please provide SSH username and either password or key path.');
      return;
    }

    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await axios.post('/api/data-collection/stop', {
        sshHost: machineIp,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
      });

      setSuccess(`Data collection stopped successfully on ${machineIp}!`);
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/data-collection/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to stop data collection. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Check if node index is already in use for the same receiver IP
    const nodeIndexNum = parseInt(formData.nodeIndex);
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
      const response = await axios.post('/api/data-collection/run', formData);
      setSuccess('Data collection started successfully!');
      
      // Refresh running instances
      const instancesResponse = await fetch('/api/data-collection/instances');
      const instancesData = await instancesResponse.json();
      setRunningInstances(instancesData.instances);
      
      // Reset form data after successful submission
      setFormData({
        sshHost: '',
        sshUsername: '',
        sshPassword: '',
        sshKeyPath: '',
        mongodbUri: '',
        mongodbDatabase: '',
        mongodbCollection: '',
        autoRestart: true,
        nodeIndex: '',
        moatPublicIp: '',
      });
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to start data collection. Please try again.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ maxWidth: 800, mx: 'auto', mb: 4 }}>
      {/* <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5">
          Data Collection Configuration
        </Typography>
      </Box> */}

      {/* Running Instances Section */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540', userSelect: 'none' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6" sx={{ userSelect: 'none' }}>
            Running Instances ({runningInstances.length})
          </Typography>
        </Box>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ userSelect: 'none' }}>Machine IP</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>PID</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Start Time</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Status</TableCell>
                <TableCell sx={{ userSelect: 'none' }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {runningInstances.length > 0 ? (
                runningInstances.map((instance) => (
                  <TableRow key={instance.instanceKey}>
                    <TableCell>{instance.machineIp}</TableCell>
                    <TableCell>{instance.pid}</TableCell>
                    <TableCell>{new Date(instance.startTime).toLocaleString()}</TableCell>
                    <TableCell>{instance.status}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button
                          variant="contained"
                          color="error"
                          size="small"
                          onClick={() => handleStopInstance(instance.pid, instance.machineIp)}
                          disabled={stopping}
                          startIcon={stopping ? <CircularProgress size={16} /> : null}
                        >
                          Stop
                        </Button>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={5} align="center">
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

      <Typography variant="h6" sx={{ mb: 2, userSelect: 'none' }}>
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
              error={runningInstances.some(instance => instance.machineIp === formData.sshHost)}
              helperText={runningInstances.some(instance => instance.machineIp === formData.sshHost) ? 
                'This machine already has a running instance' : ''}
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
        MongoDB Configuration
      </Typography>
      <Paper sx={{ p: 2, mb: 3, bgcolor: '#252540' }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="MongoDB URI"
              name="mongodbUri"
              value={formData.mongodbUri}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="MongoDB Database"
              name="mongodbDatabase"
              value={formData.mongodbDatabase}
              onChange={handleInputChange}
              required
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="MongoDB Collection"
              name="mongodbCollection"
              value={formData.mongodbCollection}
              onChange={handleInputChange}
              required
            />
          </Grid>
        </Grid>
      </Paper>

      <FormControlLabel
        control={
          <Switch
            checked={formData.autoRestart}
            onChange={handleInputChange}
            name="autoRestart"
            color="primary"
          />
        }
        label="Auto-restart on failure"
        sx={{ mt: 2, userSelect:'none' }}
      />

      <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
        <Button
          type="submit"
          variant="contained"
          fullWidth
          disabled={loading || stopping || 
            !formData.sshHost || 
            !formData.sshUsername || 
            !formData.mongodbUri || 
            !formData.mongodbDatabase || 
            !formData.mongodbCollection ||
            runningInstances.some(instance => instance.machineIp === formData.sshHost)
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
          {loading ? <CircularProgress size={24} /> : 'Start Data Collection'}
        </Button>
        <Button
          variant="contained"
          color="error"
          fullWidth
          onClick={handleStopAllInstances}
          disabled={stopping || runningInstances.length === 0}
        >
          {stopping ? <CircularProgress size={24} /> : 'Stop All'}
        </Button>
      </Box>
    </Box>
  );
};

export default DataCollection; 