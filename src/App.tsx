import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {
  AppBar,
  Box,
  Container,
  Paper,
  Tab,
  Tabs,
  Toolbar,
  Typography,
} from '@mui/material';
import TrafficGenerator from './components/TrafficGenerator';
import DataCollection from './components/DataCollection';
import logo from './assets/shugo-logo.png'; // Make sure to add your logo to src/assets/

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#03FFF6', // shugo.io bright purple
    },
    secondary: {
      main: '#7871a0', // shugo.io bright purple
    },
    background: {
      default: '#1B1B3A',  // dark blue-purple background
      paper: '#29294D',    // slightly lighter paper
    },
    text: {
      primary: '#E6E6FA',  // light lavender-ish white text
      secondary: '#B0A9C3', // muted lavender-gray text
    },
  },
  typography: {
    fontFamily: `'Poppins', 'Roboto', 'Helvetica Neue', Arial, sans-serif`,
    h6: {
      fontWeight: 600,
      letterSpacing: '0.03em',
    },
    body1: {
      fontWeight: 400,
    },
    button: {
      textTransform: 'none',
      fontWeight: 600,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#1B1B3A',
          color: '#E6E6FA',
        },
      },
    },
  },
});

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function App() {
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <AppBar position="static" elevation={0} sx={{ 
          backgroundColor: 'background.paper',
          borderBottom: '1px solid',
          borderColor: 'divider'
        }}>
          <Toolbar sx={{ justifyContent: 'center', position: 'relative' }}>
            <Typography 
              variant="h4" 
              component="div"
              sx={{ 
                fontFamily: `'Inter', 'Poppins', 'Roboto', 'Helvetica Neue', Arial, sans-serif`,
                fontWeight: 700,
                letterSpacing: '0.05em',
                background: 'linear-gradient(45deg, #00FF9D 0%, #00FF9D 40%, #03FFF6 60%, #00B8FF 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                textShadow: '0 2px 4px rgba(0,0,0,0.1)',
                position: 'absolute',
                left: '50%',
                transform: 'translateX(-50%)',
              }}
            >
              Δataprox
            </Typography>

            <Box
              component="img"
              src={logo}
              alt="Shugo Logo"
              sx={{
                height: 40,
                width: 'auto',
                cursor: 'pointer',
                position: 'absolute',
                right: 16,
                '&:hover': {
                  opacity: 0.8,
                },
              }}
              onClick={() => window.open('https://shugo.io', '_blank')}
            />
          </Toolbar>
        </AppBar>
        <Container component="main" sx={{ flexGrow: 1, py: 4 }}>
          <Paper 
            sx={{ 
              width: '100%',
              bgcolor: 'background.paper',
              color: 'text.primary'
            }}
          >
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs 
                value={tabValue} 
                onChange={handleTabChange} 
                aria-label="dashboard tabs"
                textColor="primary"
                indicatorColor="primary"
              >
                <Tab label="Traffic Generator" />
                <Tab label="Data Collection" />
              </Tabs>
            </Box>
            <TabPanel value={tabValue} index={0}>
              <TrafficGenerator />
            </TabPanel>
            <TabPanel value={tabValue} index={1}>
              <DataCollection />
            </TabPanel>
          </Paper>
        </Container>
      </Box>
    </ThemeProvider>
  );
}

export default App; 