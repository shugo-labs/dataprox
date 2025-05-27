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
} from '@mui/material';
import axios from 'axios';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';

interface TrafficGeneratorProps {}

interface ProcessDetails {
  stdout: string;
  stderr: string;
  processStatus: string;
  pid: string;
  processStatusAfter5s: string;
}

interface LogFile {
  name: string;
  size: number;
  lastModified: string;
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
    privateIp: '',
    nodeIndex: '',
    totalDuration: '',
  });
  const [loading, setLoading] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string | null>(null);
  const [processDetails, setProcessDetails] = useState<ProcessDetails | null>(null);
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [selectedLogFile, setSelectedLogFile] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [wsConnected, setWsConnected] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  useEffect(() => {
    // Fetch log files when component mounts
    fetchLogFiles();

    // Set up auto-refresh interval
    const interval = setInterval(() => {
      if (autoRefresh) {
        fetchLogFiles();
      }
    }, 5000);

    return () => {
      clearInterval(interval);
      if (ws) {
        ws.close();
      }
    };
  }, [autoRefresh, ws]);

  const fetchLogFiles = async () => {
    try {
      const response = await axios.get('/api/traffic-generator/logs');
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);
    setProcessDetails(null);

    try {
      const response = await axios.post('/api/traffic-generator/run', formData);
      setSuccess('Traffic generation started successfully!');
      if (response.data.details) {
        setProcessDetails(response.data.details);
      }
    } catch (err: any) {
      setError(err.response?.data?.details || 'Failed to start traffic generation. Please try again.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    setError(null);
    setSuccess(null);

    try {
      // First stop the traffic processes
      const stopResponse = await axios.post('/api/traffic-generator/stop', {
        sshHost: formData.sshHost,
        sshUsername: formData.sshUsername,
        sshPassword: formData.sshPassword,
        sshKeyPath: formData.sshKeyPath,
      });

      // Then cleanup the tail process if we have a PID
      if (processDetails?.pid) {
        await axios.post('/api/traffic-generator/cleanup', {
          pid: processDetails.pid,
          sshHost: formData.sshHost,
          sshUsername: formData.sshUsername,
          sshPassword: formData.sshPassword,
          sshKeyPath: formData.sshKeyPath,
        });
      }

      setSuccess('Traffic processes stopped successfully!');
      setProcessDetails(null);
    } catch (err) {
      setError('Failed to stop traffic processes. Please try again.');
      console.error('Error:', err);
    } finally {
      setStopping(false);
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ maxWidth: 800, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        Traffic Generator Configuration
      </Typography>

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

      {processDetails && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'background.paper', borderRadius: 1 }}>
          <Typography variant="h6" gutterBottom>
            Process Details
          </Typography>
          {processDetails.stdout && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Output:
              </Typography>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                {processDetails.stdout}
              </pre>
            </Box>
          )}
          {processDetails.stderr && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Errors:
              </Typography>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: 'error.main' }}>
                {processDetails.stderr}
              </pre>
            </Box>
          )}
          {processDetails.processStatus && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary">
                Process Status:
              </Typography>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                {processDetails.processStatus}
              </pre>
            </Box>
          )}
        </Box>
      )}

      <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
        SSH Connection
      </Typography>
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
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="SSH Key Path (optional)"
            name="sshKeyPath"
            value={formData.sshKeyPath}
            onChange={handleInputChange}
            helperText="Path to private key file if using key-based authentication"
          />
        </Grid>
      </Grid>

      <Button
        variant="outlined"
        color="primary"
        onClick={testConnection}
        disabled={loading || stopping}
        sx={{ mt: 2 }}
      >
        Test Connection
      </Button>

      <Divider sx={{ my: 4 }} />

      <Typography variant="h6" sx={{ mb: 2 }}>
        Traffic Generator Settings
      </Typography>
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
            label="MOAT Private IP"
            name="moatPrivateIp"
            value={formData.moatPrivateIp}
            onChange={handleInputChange}
            required
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="Private IP"
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
            type="number"
            value={formData.nodeIndex}
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

      <Stack direction="row" spacing={2} sx={{ mt: 3 }}>
        <Button
          type="submit"
          variant="contained"
          color="primary"
          fullWidth
          disabled={loading || stopping}
        >
          {loading ? <CircularProgress size={24} /> : 'Start Traffic Generation'}
        </Button>
        <Button
          variant="contained"
          color="error"
          fullWidth
          onClick={handleStop}
          disabled={loading || stopping}
        >
          {stopping ? <CircularProgress size={24} /> : 'Stop Traffic'}
        </Button>
      </Stack>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">
          Log Files
        </Typography>
        <Box>
          <Button
            startIcon={<RefreshIcon />}
            onClick={fetchLogFiles}
            disabled={loading}
          >
            Refresh
          </Button>
          <Button
            variant={autoRefresh ? 'contained' : 'outlined'}
            onClick={() => setAutoRefresh(!autoRefresh)}
            sx={{ ml: 1 }}
          >
            Auto Refresh
          </Button>
        </Box>
      </Box>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <List sx={{ bgcolor: 'background.paper', borderRadius: 1 }}>
            {logFiles.map((file) => (
              <ListItem
                key={file.name}
                secondaryAction={
                  <IconButton
                    edge="end"
                    aria-label="delete"
                    onClick={() => handleDeleteLog(file.name)}
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
                }}
              >
                <ListItemText
                  primary={file.name}
                  secondary={`${(file.size / 1024).toFixed(2)} KB - ${new Date(file.lastModified).toLocaleString()}`}
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
            }}
          >
            {selectedLogFile ? (
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                {logContent || 'Loading log content...'}
              </pre>
            ) : (
              <Typography color="text.secondary" sx={{ textAlign: 'center', mt: 2 }}>
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