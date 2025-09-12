const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');

class CertificateService {
  constructor() {
    this.certificateDir = path.join(__dirname, '../certificates');
    this.templatesDir = path.join(__dirname, '../templates');
  }

  /**
   * Generate a complete certificate package (PDF + JSON)
   * @param {Object} certificateData - Certificate information
   * @returns {Promise<Object>} - Certificate package details
   */
  async generateCertificate(certificateData) {
    try {
      // Ensure certificate directory exists
      await this.ensureDirectoryExists(this.certificateDir);

      // Generate JSON certificate
      const jsonCert = await this.generateJSONCertificate(certificateData);
      
      // Generate PDF certificate
      const pdfCert = await this.generatePDFCertificate(certificateData);
      
      // Generate QR code for verification
      const qrCode = await this.generateQRCode(certificateData.certificateId);

      return {
        certificateId: certificateData.certificateId,
        json: jsonCert,
        pdf: pdfCert,
        qrCode: qrCode,
        verificationUrl: this.getVerificationUrl(certificateData.certificateId),
        generatedAt: new Date().toISOString()
      };

    } catch (error) {
      throw new Error(`Certificate generation failed: ${error.message}`);
    }
  }

  /**
   * Generate JSON certificate with digital signature
   * @param {Object} certificateData - Certificate data
   * @returns {Promise<Object>} - JSON certificate details
   */
  async generateJSONCertificate(certificateData) {
    const jsonCertificate = {
      version: '1.0',
      standard: 'NIST SP 800-88 Rev. 1',
      issuer: {
        name: 'JNARDDC Secure Wipe Authority',
        organization: 'Ministry of Mines, Government of India',
        department: 'Jawaharlal Nehru Aluminium Research Development and Design Centre',
        country: 'India',
        website: 'https://jnarddc.gov.in'
      },
      certificate: {
        id: certificateData.certificateId,
        issuedAt: new Date().toISOString(),
        validFrom: certificateData.validFrom || new Date().toISOString(),
        validUntil: certificateData.validUntil || new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        type: 'Data Sanitization Certificate',
        classification: certificateData.classification || 'Standard'
      },
      device: {
        id: certificateData.deviceId,
        manufacturer: certificateData.deviceInfo?.manufacturer,
        model: certificateData.deviceInfo?.model,
        serialNumber: certificateData.deviceInfo?.serialNumber,
        type: certificateData.deviceInfo?.type,
        storageDevices: certificateData.deviceInfo?.storageDevices || []
      },
      sanitization: {
        method: certificateData.wipeRecord.method,
        methodDescription: this.getMethodDescription(certificateData.wipeRecord.method),
        passes: certificateData.wipeRecord.passes,
        startedAt: certificateData.wipeRecord.startedAt,
        completedAt: certificateData.wipeRecord.completedAt,
        duration: certificateData.wipeRecord.duration,
        status: certificateData.wipeRecord.status,
        sectors: {
          total: certificateData.sectors?.total || 0,
          processed: certificateData.sectors?.wiped || 0,
          verified: certificateData.sectors?.verified || 0,
          failed: certificateData.sectors?.failed || 0
        },
        verificationRate: certificateData.verificationRate || 0
      },
      compliance: {
        standard: certificateData.compliance?.standard || 'NIST_SP_800_88',
        version: certificateData.compliance?.version || 'Rev. 1',
        requirements: certificateData.compliance?.requirements || [],
        certificationLevel: certificateData.compliance?.certificationLevel || 'basic',
        attestation: 'This certificate attests that the specified storage device has been sanitized in accordance with NIST SP 800-88 guidelines.'
      },
      technician: {
        id: certificateData.technician?.userId,
        name: certificateData.technician?.name,
        email: certificateData.technician?.email,
        organization: certificateData.technician?.credentials?.organization,
        licenseNumber: certificateData.technician?.credentials?.licenseNumber,
        certifications: certificateData.technician?.credentials?.certifications || []
      },
      verification: {
        method: 'Automated Random Sampling',
        checksum: certificateData.verification?.automated?.checksum,
        randomSampling: certificateData.verification?.automated?.randomSampling,
        timestamp: certificateData.verification?.automated?.timestamp,
        thirdPartyRequired: certificateData.verification?.thirdParty?.required || false,
        thirdPartyStatus: certificateData.verification?.thirdParty?.status || 'not_required'
      },
      metadata: {
        generatedBy: 'JNARDDC Secure Data Wiper v1.0',
        generatedAt: new Date().toISOString(),
        format: 'JSON',
        encoding: 'UTF-8',
        checksum: null, // Will be calculated after signing
        digitalSignature: null // Will be added during signing
      }
    };

    // Calculate checksum before signing
    const contentForChecksum = JSON.stringify(jsonCertificate, null, 2);
    jsonCertificate.metadata.checksum = crypto.createHash('sha256').update(contentForChecksum).digest('hex');

    // Sign the certificate
    const signature = await this.signCertificate(jsonCertificate);
    jsonCertificate.metadata.digitalSignature = signature;

    // Save JSON certificate to file
    const filename = `certificate_${certificateData.certificateId}.json`;
    const filepath = path.join(this.certificateDir, filename);
    
    await fs.writeFile(filepath, JSON.stringify(jsonCertificate, null, 2), 'utf8');
    
    const stats = await fs.stat(filepath);

    return {
      filename,
      filepath,
      size: stats.size,
      checksum: crypto.createHash('sha256').update(JSON.stringify(jsonCertificate)).digest('hex'),
      content: jsonCertificate
    };
  }

  /**
   * Generate PDF certificate
   * @param {Object} certificateData - Certificate data
   * @returns {Promise<Object>} - PDF certificate details
   */
  async generatePDFCertificate(certificateData) {
    const filename = `certificate_${certificateData.certificateId}.pdf`;
    const filepath = path.join(this.certificateDir, filename);

    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ 
          size: 'A4', 
          margins: { top: 50, bottom: 50, left: 50, right: 50 }
        });
        
        const stream = require('fs').createWriteStream(filepath);
        doc.pipe(stream);

        // Header
        await this.addPDFHeader(doc, certificateData);
        
        // Certificate Title
        await this.addPDFTitle(doc);
        
        // Certificate Information
        await this.addPDFCertificateInfo(doc, certificateData);
        
        // Device Information
        await this.addPDFDeviceInfo(doc, certificateData);
        
        // Sanitization Details
        await this.addPDFSanitizationDetails(doc, certificateData);
        
        // Compliance Information
        await this.addPDFComplianceInfo(doc, certificateData);
        
        // Verification Details
        await this.addPDFVerificationDetails(doc, certificateData);
        
        // Digital Signature Section
        await this.addPDFSignatureSection(doc, certificateData);
        
        // QR Code for verification
        await this.addPDFQRCode(doc, certificateData.certificateId);
        
        // Footer
        await this.addPDFFooter(doc, certificateData);

        doc.end();

        stream.on('finish', async () => {
          try {
            const stats = await fs.stat(filepath);
            const buffer = await fs.readFile(filepath);
            const checksum = crypto.createHash('sha256').update(buffer).digest('hex');

            resolve({
              filename,
              filepath,
              size: stats.size,
              checksum
            });
          } catch (error) {
            reject(error);
          }
        });

        stream.on('error', reject);

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Add PDF header with official branding
   * @private
   */
  async addPDFHeader(doc, certificateData) {
    // Government of India Header
    doc.fontSize(20).fillColor('#FF8C00').text('Government of India', 50, 50);
    doc.fontSize(16).fillColor('#000080').text('Ministry of Mines', 50, 75);
    doc.fontSize(14).fillColor('#000').text('Jawaharlal Nehru Aluminium Research Development and Design Centre (JNARDDC)', 50, 95);
    
    // Horizontal line
    doc.strokeColor('#FF8C00').lineWidth(2)
       .moveTo(50, 120).lineTo(545, 120).stroke();
    
    // Certificate security features
    doc.fontSize(10).fillColor('#666')
       .text(`Certificate ID: ${certificateData.certificateId}`, 400, 50)
       .text(`Generated: ${new Date().toLocaleDateString('en-IN')}`, 400, 65)
       .text(`Time: ${new Date().toLocaleTimeString('en-IN')}`, 400, 80);

    doc.moveDown(3);
  }

  /**
   * Add PDF certificate title
   * @private
   */
  async addPDFTitle(doc) {
    doc.fontSize(24).fillColor('#000080')
       .text('SECURE DATA SANITIZATION CERTIFICATE', 50, 150, { align: 'center' });
    
    doc.fontSize(14).fillColor('#000')
       .text('In compliance with NIST SP 800-88 Rev. 1 Guidelines for Media Sanitization', 50, 180, { align: 'center' });
    
    doc.moveDown(2);
  }

  /**
   * Add certificate information section
   * @private
   */
  async addPDFCertificateInfo(doc, certificateData) {
    const y = 220;
    
    doc.fontSize(16).fillColor('#000080').text('CERTIFICATE INFORMATION', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(250, y + 20).stroke();
    
    doc.fontSize(11).fillColor('#000')
       .text(`Certificate ID: ${certificateData.certificateId}`, 50, y + 30)
       .text(`Issue Date: ${new Date().toLocaleDateString('en-IN')}`, 50, y + 45)
       .text(`Valid From: ${new Date(certificateData.validFrom || Date.now()).toLocaleDateString('en-IN')}`, 50, y + 60)
       .text(`Valid Until: ${new Date(certificateData.validUntil || Date.now() + 5*365*24*60*60*1000).toLocaleDateString('en-IN')}`, 50, y + 75)
       .text(`Classification: ${certificateData.classification || 'Standard'}`, 300, y + 30)
       .text(`Compliance: NIST SP 800-88 Rev. 1`, 300, y + 45)
       .text(`Security Level: ${certificateData.compliance?.certificationLevel || 'Basic'}`, 300, y + 60);

    doc.moveDown(6);
  }

  /**
   * Add device information section
   * @private
   */
  async addPDFDeviceInfo(doc, certificateData) {
    const y = doc.y + 10;
    
    doc.fontSize(16).fillColor('#000080').text('DEVICE INFORMATION', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(200, y + 20).stroke();
    
    doc.fontSize(11).fillColor('#000')
       .text(`Device ID: ${certificateData.deviceId}`, 50, y + 30)
       .text(`Manufacturer: ${certificateData.deviceInfo?.manufacturer || 'N/A'}`, 50, y + 45)
       .text(`Model: ${certificateData.deviceInfo?.model || 'N/A'}`, 50, y + 60)
       .text(`Serial Number: ${certificateData.deviceInfo?.serialNumber || 'N/A'}`, 50, y + 75)
       .text(`Device Type: ${certificateData.deviceInfo?.type || 'N/A'}`, 300, y + 30);

    // Storage devices details
    if (certificateData.deviceInfo?.storageDevices?.length > 0) {
      doc.text('Storage Devices:', 300, y + 45);
      certificateData.deviceInfo.storageDevices.forEach((storage, index) => {
        doc.fontSize(10)
           .text(`• ${storage.type} - ${storage.capacity}GB (${storage.model || 'Unknown'})`, 
                 320, y + 60 + (index * 12));
      });
    }

    doc.moveDown(6);
  }

  /**
   * Add sanitization details section
   * @private
   */
  async addPDFSanitizationDetails(doc, certificateData) {
    const y = doc.y + 10;
    
    doc.fontSize(16).fillColor('#000080').text('SANITIZATION DETAILS', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(220, y + 20).stroke();
    
    const method = certificateData.wipeRecord.method;
    const methodDesc = this.getMethodDescription(method);
    
    doc.fontSize(11).fillColor('#000')
       .text(`Method: ${method.toUpperCase().replace(/_/g, ' ')}`, 50, y + 30)
       .text(`Description: ${methodDesc}`, 50, y + 45, { width: 480 })
       .text(`Passes: ${certificateData.wipeRecord.passes}`, 50, y + 75)
       .text(`Started: ${new Date(certificateData.wipeRecord.startedAt).toLocaleString('en-IN')}`, 50, y + 90)
       .text(`Completed: ${new Date(certificateData.wipeRecord.completedAt).toLocaleString('en-IN')}`, 50, y + 105)
       .text(`Duration: ${Math.round(certificateData.wipeRecord.duration)} minutes`, 300, y + 75)
       .text(`Status: ${certificateData.wipeRecord.status.toUpperCase()}`, 300, y + 90);

    // Sector statistics
    if (certificateData.sectors) {
      doc.text('Sector Statistics:', 50, y + 130)
         .text(`Total Sectors: ${certificateData.sectors.total?.toLocaleString() || 'N/A'}`, 70, y + 145)
         .text(`Processed: ${certificateData.sectors.wiped?.toLocaleString() || 'N/A'}`, 70, y + 160)
         .text(`Verified: ${certificateData.sectors.verified?.toLocaleString() || 'N/A'}`, 300, y + 145)
         .text(`Failed: ${certificateData.sectors.failed || 0}`, 300, y + 160);
    }

    doc.moveDown(8);
  }

  /**
   * Add compliance information section
   * @private
   */
  async addPDFComplianceInfo(doc, certificateData) {
    const y = doc.y + 10;
    
    doc.fontSize(16).fillColor('#000080').text('COMPLIANCE & ATTESTATION', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(270, y + 20).stroke();
    
    doc.fontSize(11).fillColor('#000')
       .text('This certificate attests that:', 50, y + 35)
       .text('• The specified storage device has been sanitized in accordance with NIST SP 800-88 Rev. 1', 60, y + 55)
       .text('• All user-accessible data areas have been overwritten using approved methods', 60, y + 70)
       .text('• Random verification sampling confirms successful data destruction', 60, y + 85)
       .text('• The sanitization process meets or exceeds industry security standards', 60, y + 100);

    if (certificateData.verificationRate) {
      doc.text(`Verification Success Rate: ${certificateData.verificationRate.toFixed(2)}%`, 60, y + 115);
    }

    doc.moveDown(8);
  }

  /**
   * Add verification details section
   * @private
   */
  async addPDFVerificationDetails(doc, certificateData) {
    const y = doc.y + 10;
    
    doc.fontSize(16).fillColor('#000080').text('VERIFICATION DETAILS', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(200, y + 20).stroke();
    
    doc.fontSize(11).fillColor('#000')
       .text(`Verification Method: ${certificateData.verification?.method || 'Automated Random Sampling'}`, 50, y + 30)
       .text(`Checksum: ${(certificateData.verification?.automated?.checksum || 'N/A').substring(0, 32)}...`, 50, y + 45)
       .text(`Timestamp: ${new Date(certificateData.verification?.automated?.timestamp || Date.now()).toLocaleString('en-IN')}`, 50, y + 60);

    if (certificateData.verification?.thirdParty?.required) {
      doc.text('Third-Party Verification: Required', 300, y + 30)
         .text(`Status: ${certificateData.verification.thirdParty.status || 'Pending'}`, 300, y + 45);
    }

    doc.moveDown(6);
  }

  /**
   * Add digital signature section
   * @private
   */
  async addPDFSignatureSection(doc, certificateData) {
    const y = doc.y + 10;
    
    doc.fontSize(16).fillColor('#000080').text('DIGITAL SIGNATURE', 50, y);
    doc.strokeColor('#000080').lineWidth(1).moveTo(50, y + 20).lineTo(180, y + 20).stroke();
    
    doc.fontSize(11).fillColor('#000')
       .text('Technician:', 50, y + 35)
       .text(`Name: ${certificateData.technician?.name || 'N/A'}`, 70, y + 50)
       .text(`Email: ${certificateData.technician?.email || 'N/A'}`, 70, y + 65)
       .text(`Organization: ${certificateData.technician?.credentials?.organization || 'JNARDDC'}`, 70, y + 80)
       .text(`License: ${certificateData.technician?.credentials?.licenseNumber || 'N/A'}`, 300, y + 50);

    // Digital signature placeholder
    doc.fontSize(10).fillColor('#666')
       .text('Digitally signed certificate - Signature details available in JSON format', 50, y + 105)
       .text(`Certificate Authority: JNARDDC Secure Wipe Authority`, 50, y + 120)
       .text(`Signature Algorithm: RSA-SHA256`, 50, y + 135);

    doc.moveDown(8);
  }

  /**
   * Add QR code for verification
   * @private
   */
  async addPDFQRCode(doc, certificateId) {
    try {
      const verificationUrl = this.getVerificationUrl(certificateId);
      const qrCodeDataUrl = await QRCode.toDataURL(verificationUrl, {
        width: 100,
        margin: 1
      });
      
      // Convert data URL to buffer
      const base64Data = qrCodeDataUrl.replace(/^data:image\/png;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      
      // Add QR code to PDF
      doc.image(buffer, 450, doc.y - 100, { width: 80, height: 80 });
      doc.fontSize(8).fillColor('#666')
         .text('Scan to verify certificate', 445, doc.y - 10);
    } catch (error) {
      console.warn('Failed to add QR code to PDF:', error.message);
    }
  }

  /**
   * Add PDF footer
   * @private
   */
  async addPDFFooter(doc, certificateData) {
    const pageHeight = doc.page.height;
    const footerY = pageHeight - 60;
    
    // Footer line
    doc.strokeColor('#FF8C00').lineWidth(1)
       .moveTo(50, footerY - 10).lineTo(545, footerY - 10).stroke();
    
    doc.fontSize(8).fillColor('#666')
       .text('This is a digitally generated certificate. Verify authenticity at https://verify.jnarddc.gov.in', 50, footerY)
       .text(`Generated by JNARDDC Secure Data Wiper v1.0 | Document ID: ${certificateData.certificateId}`, 50, footerY + 12)
       .text(`© ${new Date().getFullYear()} Ministry of Mines, Government of India`, 50, footerY + 24);
  }

  /**
   * Generate QR code for certificate verification
   * @param {string} certificateId - Certificate ID
   * @returns {Promise<Object>} - QR code details
   */
  async generateQRCode(certificateId) {
    const verificationUrl = this.getVerificationUrl(certificateId);
    
    const qrCodeDataUrl = await QRCode.toDataURL(verificationUrl, {
      width: 200,
      margin: 2,
      color: {
        dark: '#000080',
        light: '#FFFFFF'
      }
    });

    return {
      data: qrCodeDataUrl,
      verificationUrl,
      format: 'PNG',
      size: '200x200'
    };
  }

  /**
   * Sign certificate with digital signature
   * @param {Object} certificateData - Certificate data to sign
   * @returns {Promise<Object>} - Digital signature
   */
  async signCertificate(certificateData) {
    try {
      // Generate key pair for signing (in production, use proper key management)
      const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      
      // Create certificate content for signing
      const content = JSON.stringify({
        certificateId: certificateData.certificate.id,
        deviceId: certificateData.device.id,
        sanitization: certificateData.sanitization,
        compliance: certificateData.compliance,
        timestamp: certificateData.metadata.generatedAt
      });

      // Create signature
      const md = forge.md.sha256.create();
      md.update(content, 'utf8');
      const signature = keyPair.privateKey.sign(md);
      
      // Convert to base64
      const signatureB64 = forge.util.encode64(signature);
      
      // Get public key in PEM format
      const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);

      return {
        algorithm: 'RSA-SHA256',
        signature: signatureB64,
        publicKey: publicKeyPem,
        timestamp: new Date().toISOString(),
        issuer: 'JNARDDC Secure Wipe Authority'
      };

    } catch (error) {
      throw new Error(`Certificate signing failed: ${error.message}`);
    }
  }

  /**
   * Verify certificate signature
   * @param {Object} certificate - Certificate with signature
   * @returns {boolean} - Verification result
   */
  async verifyCertificateSignature(certificate) {
    try {
      const signature = certificate.metadata.digitalSignature;
      if (!signature) return false;

      // Recreate the signed content
      const content = JSON.stringify({
        certificateId: certificate.certificate.id,
        deviceId: certificate.device.id,
        sanitization: certificate.sanitization,
        compliance: certificate.compliance,
        timestamp: signature.timestamp
      });

      // Convert public key and signature
      const publicKey = forge.pki.publicKeyFromPem(signature.publicKey);
      const signatureBytes = forge.util.decode64(signature.signature);
      
      // Verify signature
      const md = forge.md.sha256.create();
      md.update(content, 'utf8');
      
      return publicKey.verify(md.digest().bytes(), signatureBytes);

    } catch (error) {
      console.error('Signature verification failed:', error.message);
      return false;
    }
  }

  /**
   * Get method description for display
   * @private
   */
  getMethodDescription(method) {
    const descriptions = {
      'nist_clear': 'Single pass overwrite with zeros as per NIST SP 800-88 Clear method',
      'nist_purge': 'Three pass purge method as per NIST SP 800-88 Purge guidelines',
      'dod_3pass': 'DoD 5220.22-M three-pass method with zeros, ones, and random data',
      'dod_7pass': 'DoD 5220.22-M seven-pass method for high security applications',
      'gutmann': 'Peter Gutmann\'s 35-pass method for maximum theoretical security',
      'random_overwrite': 'Single pass overwrite with cryptographically secure random data',
      'crypto_erase': 'Cryptographic erasure through encryption key destruction'
    };
    return descriptions[method] || 'Custom sanitization method';
  }

  /**
   * Get verification URL for certificate
   * @param {string} certificateId - Certificate ID
   * @returns {string} - Verification URL
   */
  getVerificationUrl(certificateId) {
    const baseUrl = process.env.VERIFICATION_BASE_URL || 'https://verify.jnarddc.gov.in';
    return `${baseUrl}/verify/${certificateId}`;
  }

  /**
   * Ensure directory exists
   * @private
   */
  async ensureDirectoryExists(dirPath) {
    try {
      await fs.access(dirPath);
    } catch (error) {
      await fs.mkdir(dirPath, { recursive: true });
    }
  }

  /**
   * Read certificate from file
   * @param {string} certificateId - Certificate ID
   * @returns {Promise<Object>} - Certificate data
   */
  async readCertificate(certificateId) {
    const jsonPath = path.join(this.certificateDir, `certificate_${certificateId}.json`);
    
    try {
      const data = await fs.readFile(jsonPath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      throw new Error(`Certificate not found: ${certificateId}`);
    }
  }

  /**
   * List all certificates
   * @returns {Promise<Array>} - List of certificates
   */
  async listCertificates() {
    try {
      const files = await fs.readdir(this.certificateDir);
      const certificates = [];
      
      for (const file of files) {
        if (file.endsWith('.json') && file.startsWith('certificate_')) {
          const certificateId = file.replace('certificate_', '').replace('.json', '');
          try {
            const certificate = await this.readCertificate(certificateId);
            certificates.push({
              id: certificateId,
              issuedAt: certificate.certificate.issuedAt,
              deviceId: certificate.device.id,
              method: certificate.sanitization.method,
              status: certificate.sanitization.status
            });
          } catch (error) {
            console.warn(`Failed to read certificate ${certificateId}:`, error.message);
          }
        }
      }
      
      return certificates.sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));
    } catch (error) {
      return [];
    }
  }

  /**
   * Delete certificate files
   * @param {string} certificateId - Certificate ID
   * @returns {Promise<boolean>} - Success status
   */
  async deleteCertificate(certificateId) {
    try {
      const jsonPath = path.join(this.certificateDir, `certificate_${certificateId}.json`);
      const pdfPath = path.join(this.certificateDir, `certificate_${certificateId}.pdf`);
      
      await fs.unlink(jsonPath).catch(() => {});
      await fs.unlink(pdfPath).catch(() => {});
      
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = CertificateService;