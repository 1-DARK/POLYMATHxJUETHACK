import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { QueryClient, QueryClientProvider } from 'react-query';
import { SnackbarProvider } from 'notistack';

// Contexts
import { AuthProvider } from './contexts/AuthContext';
import { WipeProvider } from './contexts/WipeContext';

// Components
import Layout from './components/Layout/Layout';
import ProtectedRoute from './components/Auth/ProtectedRoute';

// Pages
import Login from './pages/Auth/Login';
import Register from './pages/Auth/Register';
import Dashboard from './pages/Dashboard/Dashboard';
import WipeDevice from './pages/Wipe/WipeDevice';
import WipeProgress from './pages/Wipe/WipeProgress';
import Certificates from './pages/Certificates/Certificates';
import CertificateView from './pages/Certificates/CertificateView';
import Devices from './pages/Devices/Devices';
import Settings from './pages/Settings/Settings';
import Verification from './pages/Verification/Verification';
import About from './pages/About/About';

// Create query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

// Create Material-UI theme with Indian government colors
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#000080', // Navy Blue (Government of India)
      light: '#3333a3',
      dark: '#000059',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#FF8C00', // Saffron Orange (Indian Flag)
      light: '#ffad42',
      dark: '#c45e00',
      contrastText: '#ffffff',
    },
    success: {
      main: '#138808', // Green (Indian Flag)
      light: '#4caf50',
      dark: '#087f23',
    },
    warning: {
      main: '#ff9800',
      light: '#ffb74d',
      dark: '#f57c00',
    },
    error: {
      main: '#f44336',
      light: '#ef5350',
      dark: '#c62828',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
    text: {
      primary: '#1a1a1a',
      secondary: '#666666',
    }
  },
  typography: {
    fontFamily: '"Roboto", "Inter", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 600,
      color: '#000080',
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
      color: '#000080',
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 500,
      color: '#000080',
    },
    h4: {
      fontSize: '1.25rem',
      fontWeight: 500,
    },
    h5: {
      fontSize: '1.125rem',
      fontWeight: 500,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 500,
    },
    button: {
      textTransform: 'none',
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '8px 16px',
          boxShadow: 'none',
          '&:hover': {
            boxShadow: '0 2px 8px rgba(0, 0, 128, 0.2)',
          },
        },
        contained: {
          background: 'linear-gradient(45deg, #000080 30%, #3333a3 90%)',
          '&:hover': {
            background: 'linear-gradient(45deg, #000059 30%, #2626a0 90%)',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 12px rgba(0, 0, 0, 0.08)',
          border: '1px solid rgba(0, 0, 0, 0.06)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 8,
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: 'linear-gradient(45deg, #000080 30%, #3333a3 90%)',
          boxShadow: '0 2px 12px rgba(0, 0, 128, 0.15)',
        },
      },
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <SnackbarProvider 
          maxSnack={3}
          anchorOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
          autoHideDuration={5000}
        >
          <Router>
            <AuthProvider>
              <WipeProvider>
                <Routes>
                  {/* Public Routes */}
                  <Route path="/login" element={<Login />} />
                  <Route path="/register" element={<Register />} />
                  <Route path="/verify/:certificateId" element={<Verification />} />
                  <Route path="/about" element={<About />} />
                  
                  {/* Protected Routes */}
                  <Route
                    path="/"
                    element={
                      <ProtectedRoute>
                        <Layout />
                      </ProtectedRoute>
                    }
                  >
                    <Route index element={<Dashboard />} />
                    <Route path="dashboard" element={<Dashboard />} />
                    
                    {/* Device Management */}
                    <Route path="devices" element={<Devices />} />
                    <Route path="wipe/new" element={<WipeDevice />} />
                    <Route path="wipe/progress/:wipeId" element={<WipeProgress />} />
                    
                    {/* Certificates */}
                    <Route path="certificates" element={<Certificates />} />
                    <Route path="certificates/:certificateId" element={<CertificateView />} />
                    
                    {/* Settings */}
                    <Route path="settings" element={<Settings />} />
                    
                    {/* Fallback */}
                    <Route path="*" element={<Navigate to="/dashboard" replace />} />
                  </Route>
                </Routes>
              </WipeProvider>
            </AuthProvider>
          </Router>
        </SnackbarProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;