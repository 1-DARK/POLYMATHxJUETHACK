const express = require('express');
const Device = require('../models/Device');
const router = express.Router();

// Get all devices
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const devices = await Device.find({ isActive: true })
      .populate('owner', 'username email profile.firstName profile.lastName')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Device.countDocuments({ isActive: true });

    res.json({
      devices,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching devices', error: error.message });
  }
});

// Create new device
router.post('/', async (req, res) => {
  try {
    const deviceData = req.body;
    const device = new Device(deviceData);
    await device.save();

    res.status(201).json({
      message: 'Device created successfully',
      device
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating device', error: error.message });
  }
});

// Get device by ID
router.get('/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const device = await Device.findOne({ deviceId, isActive: true })
      .populate('owner', 'username email profile.firstName profile.lastName');
    
    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    res.json(device);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching device', error: error.message });
  }
});

// Update device
router.put('/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const updateData = req.body;

    const device = await Device.findOneAndUpdate(
      { deviceId, isActive: true },
      updateData,
      { new: true, runValidators: true }
    );

    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    res.json({
      message: 'Device updated successfully',
      device
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating device', error: error.message });
  }
});

// Get devices by status
router.get('/status/:status', async (req, res) => {
  try {
    const { status } = req.params;
    const devices = await Device.findByStatus(status);
    res.json({ devices });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching devices by status', error: error.message });
  }
});

// Get device statistics
router.get('/stats/summary', async (req, res) => {
  try {
    const stats = await Device.getWipeStatistics();
    res.json({ statistics: stats });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching device statistics', error: error.message });
  }
});

module.exports = router;