import React, { useState } from 'react';
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
} from '@mui/material';
import axios from 'axios';

interface DataCollectionProps {}

const DataCollection: React.FC<DataCollectionProps> = () => {
  const [formData, setFormData] = useState({
    // SSH Configuration
    sshHost: '',
    sshUsername: '',
    sshPassword: '',
    sshKeyPath: '',
    // MongoDB Configuration
    mongodbUsername: '',
    mongodbPassword: '',
    mongodbHost: '',
    mongodbDatabase: '',
    mongodbCollection: '',
    autoRestart: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string | null>(null);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await axios.post('/api/data-collection/run', formData);
      setSuccess('Data collection started successfully!');
    } catch (err) {
      setError('Failed to start data collection. Please try again.');
      console.error('Error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ maxWidth: 800, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        Data Collection Configuration
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
            helperText="Password file if using pwd authentication"
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

      <Button
        variant="outlined"
        color="primary"
        onClick={testConnection}
        disabled={loading}
        sx={{ mt: 2 }}
      >
        Test Connection
      </Button>

      <Divider sx={{ my: 4 }} />

      <Typography variant="h6" sx={{ mb: 2 }}>
        MongoDB Configuration
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="MongoDB Username"
            name="mongodbUsername"
            value={formData.mongodbUsername}
            onChange={handleInputChange}
            required
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="MongoDB Password"
            name="mongodbPassword"
            type="password"
            value={formData.mongodbPassword}
            onChange={handleInputChange}
            required
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="MongoDB Host"
            name="mongodbHost"
            value={formData.mongodbHost}
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
        sx={{ mt: 2 }}
      />

      <Button
        type="submit"
        variant="contained"
        color="primary"
        fullWidth
        sx={{ mt: 3 }}
        disabled={loading}
      >
        {loading ? <CircularProgress size={24} /> : 'Start Data Collection'}
      </Button>
    </Box>
  );
};

export default DataCollection; 