const express = require('express');
const WipingService = require('../services/WipingService');
const router = express.Router();

const wipingService = new WipingService();

// Get supported wiping methods
router.get('/methods', (req, res) => {
  try {
    const methods = wipingService.getSupportedMethods();
    res.json(methods);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching wiping methods', error: error.message });
  }
});

// Start a new wipe operation
router.post('/start', async (req, res) => {
  try {
    const { devicePath, method, userId, deviceId } = req.body;

    if (!devicePath || !method) {
      return res.status(400).json({ message: 'Device path and method are required' });
    }

    const wipeId = await wipingService.startWipe({
      devicePath,
      method,
      userId,
      deviceId,
      verificationEnabled: true
    });

    res.json({
      message: 'Wipe operation started successfully',
      wipeId
    });

  } catch (error) {
    res.status(500).json({ message: 'Error starting wipe operation', error: error.message });
  }
});

// Get wipe status
router.get('/status/:wipeId', (req, res) => {
  try {
    const { wipeId } = req.params;
    const status = wipingService.getWipeStatus(wipeId);
    res.json(status);
  } catch (error) {
    res.status(404).json({ message: 'Wipe not found', error: error.message });
  }
});

// Cancel wipe operation
router.post('/cancel/:wipeId', async (req, res) => {
  try {
    const { wipeId } = req.params;
    const success = await wipingService.cancelWipe(wipeId);
    
    if (success) {
      res.json({ message: 'Wipe operation cancelled successfully' });
    } else {
      res.status(400).json({ message: 'Unable to cancel wipe operation' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error cancelling wipe operation', error: error.message });
  }
});

// Get active wipes
router.get('/active', (req, res) => {
  try {
    const activeWipes = wipingService.getActiveWipes();
    res.json(activeWipes);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching active wipes', error: error.message });
  }
});

module.exports = router;