const express = require('express');
const CertificateService = require('../services/CertificateService');
const Certificate = require('../models/Certificate');
const router = express.Router();

const certificateService = new CertificateService();

// Generate new certificate
router.post('/generate', async (req, res) => {
  try {
    const certificateData = req.body;
    
    if (!certificateData.deviceId || !certificateData.wipeRecord) {
      return res.status(400).json({ message: 'Device ID and wipe record are required' });
    }

    const certificate = await certificateService.generateCertificate(certificateData);
    res.json({
      message: 'Certificate generated successfully',
      certificate
    });

  } catch (error) {
    res.status(500).json({ message: 'Error generating certificate', error: error.message });
  }
});

// Get certificate by ID
router.get('/:certificateId', async (req, res) => {
  try {
    const { certificateId } = req.params;
    const certificate = await Certificate.findOne({ certificateId });
    
    if (!certificate) {
      return res.status(404).json({ message: 'Certificate not found' });
    }

    res.json(certificate);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching certificate', error: error.message });
  }
});

// List all certificates
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const certificates = await Certificate.find({})
      .populate('device', 'deviceId deviceInfo')
      .populate('technician.userId', 'username email profile.firstName profile.lastName')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Certificate.countDocuments();

    res.json({
      certificates,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching certificates', error: error.message });
  }
});

// Download certificate (PDF)
router.get('/:certificateId/download', async (req, res) => {
  try {
    const { certificateId } = req.params;
    const { format } = req.query; // 'pdf' or 'json'
    
    const certificate = await Certificate.findOne({ certificateId });
    if (!certificate) {
      return res.status(404).json({ message: 'Certificate not found' });
    }

    if (format === 'pdf' && certificate.documents.pdf.generated) {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${certificate.documents.pdf.filename}"`);
      // In a real implementation, you would stream the file
      res.json({ message: 'PDF download would start here', path: certificate.documents.pdf.path });
    } else if (format === 'json' && certificate.documents.json.generated) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${certificate.documents.json.filename}"`);
      res.json(certificate.documents.json.content);
    } else {
      res.status(400).json({ message: 'Invalid format or certificate not generated' });
    }

    // Update download statistics
    await certificate.incrementStats('download');

  } catch (error) {
    res.status(500).json({ message: 'Error downloading certificate', error: error.message });
  }
});

module.exports = router;