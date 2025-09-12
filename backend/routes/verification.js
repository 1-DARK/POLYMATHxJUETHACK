const express = require('express');
const VerificationService = require('../services/VerificationService');
const router = express.Router();

const verificationService = new VerificationService();

// Verify certificate by ID
router.get('/:certificateId', async (req, res) => {
  try {
    const { certificateId } = req.params;
    const verification = await verificationService.verifyCertificate(certificateId);
    res.json(verification);
  } catch (error) {
    res.status(500).json({ message: 'Error verifying certificate', error: error.message });
  }
});

// Batch verify certificates
router.post('/batch', async (req, res) => {
  try {
    const { certificateIds } = req.body;
    
    if (!Array.isArray(certificateIds) || certificateIds.length === 0) {
      return res.status(400).json({ message: 'Certificate IDs array is required' });
    }

    const results = await verificationService.batchVerifyCertificates(certificateIds);
    res.json({ results });
  } catch (error) {
    res.status(500).json({ message: 'Error performing batch verification', error: error.message });
  }
});

// Generate verification report
router.get('/:certificateId/report', async (req, res) => {
  try {
    const { certificateId } = req.params;
    const report = await verificationService.generateVerificationReport(certificateId);
    res.json(report);
  } catch (error) {
    res.status(500).json({ message: 'Error generating verification report', error: error.message });
  }
});

module.exports = router;