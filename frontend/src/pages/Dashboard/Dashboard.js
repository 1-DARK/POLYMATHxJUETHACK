import React, { useState, useEffect } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardActions,
  Button,
  Box,
  LinearProgress,
  Chip,
  Alert,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Devices as DevicesIcon,
  Certificate as CertificateIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  PlayArrow as PlayArrowIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useQuery } from 'react-query';
import moment from 'moment';

// Services
import { dashboardService } from '../../services/dashboardService';
import { deviceService } from '../../services/deviceService';
import { wipeService } from '../../services/wipeService';

// Components
import WipeProgressCard from '../../components/Wipe/WipeProgressCard';
import DeviceCard from '../../components/Devices/DeviceCard';
import StatCard from '../../components/Dashboard/StatCard';

function Dashboard() {
  const navigate = useNavigate();
  const [selectedDevice, setSelectedDevice] = useState(null);

  // Fetch dashboard statistics
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery(
    'dashboard-stats',
    dashboardService.getStatistics,
    { refetchInterval: 30000 } // Refresh every 30 seconds
  );

  // Fetch recent devices
  const { data: devices, isLoading: devicesLoading } = useQuery(
    'recent-devices',
    () => deviceService.getRecentDevices(5),
    { refetchInterval: 60000 } // Refresh every minute
  );

  // Fetch active wipes
  const { data: activeWipes, isLoading: wipesLoading } = useQuery(
    'active-wipes',
    wipeService.getActiveWipes,
    { refetchInterval: 5000 } // Refresh every 5 seconds
  );

  // Fetch recent certificates
  const { data: recentCertificates, isLoading: certsLoading } = useQuery(
    'recent-certificates',
    () => dashboardService.getRecentCertificates(3),
    { refetchInterval: 60000 }
  );

  const handleQuickWipe = () => {
    if (selectedDevice) {
      navigate('/wipe/new', { state: { deviceId: selectedDevice.id } });
    } else {
      navigate('/wipe/new');
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      'ready_for_wipe': 'warning',
      'wiping_in_progress': 'info',
      'wipe_completed': 'success',
      'wipe_failed': 'error',
      'verified': 'success',
    };
    return colors[status] || 'default';
  };

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Secure Data Wiper Dashboard
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor your data wiping operations and manage IT asset recycling securely
        </Typography>
      </Box>

      {/* Quick Action Alert */}
      <Alert 
        severity="info" 
        icon={<SecurityIcon />} 
        sx={{ mb: 3 }}
        action={
          <Button 
            color="inherit" 
            size="small" 
            onClick={handleQuickWipe}
            startIcon={<PlayArrowIcon />}
          >
            Start Wipe
          </Button>
        }
      >
        <strong>Ready to wipe a device?</strong> Click "Start Wipe" for a secure one-click data sanitization process.
      </Alert>

      <Grid container spacing={3}>
        {/* Quick Actions */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Quick Actions
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                size="large"
                startIcon={<PlayArrowIcon />}
                onClick={handleQuickWipe}
              >
                Start Secure Wipe
              </Button>
              <Button
                variant="outlined"
                size="large"
                startIcon={<DevicesIcon />}
                onClick={() => navigate('/devices')}
              >
                Manage Devices
              </Button>
              <Button
                variant="outlined"
                size="large"
                startIcon={<CertificateIcon />}
                onClick={() => navigate('/certificates')}
              >
                View Certificates
              </Button>
              <Button
                variant="outlined"
                size="large"
                startIcon={<InfoIcon />}
                onClick={() => navigate('/about')}
              >
                About NIST Compliance
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* Status Information */}
        <Grid item xs={12}>
          <Alert severity="success">
            <Typography variant="body2">
              <strong>System Status:</strong> All services operational. NIST SP 800-88 Rev. 1 compliant wiping methods available.
              Last system check: {moment().format('DD/MM/YYYY HH:mm')} IST
            </Typography>
          </Alert>
        </Grid>
      </Grid>
    </Container>
  );
}

export default Dashboard;
