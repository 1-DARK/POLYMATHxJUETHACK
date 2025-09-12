const crypto = require('crypto');
const axios = require('axios');
const forge = require('node-forge');
const moment = require('moment');

class VerificationService {
  constructor() {
    this.verificationEndpoint = process.env.VERIFICATION_API_ENDPOINT || 'https://verify.jnarddc.gov.in';
    this.apiKey = process.env.VERIFICATION_API_KEY;
    this.trustedAuthorities = [
      'JNARDDC Secure Wipe Authority',
      'Ministry of Mines Verification Authority',
      'Government of India Digital Certificate Authority'
    ];
  }

  /**
   * Verify a certificate by ID
   * @param {string} certificateId - Certificate ID to verify
   * @returns {Promise<Object>} - Verification result
   */
  async verifyCertificate(certificateId) {
    try {
      // Load certificate from database
      const Certificate = require('../models/Certificate');
      const certificate = await Certificate.findOne({ certificateId });

      if (!certificate) {
        return {
          valid: false,
          error: 'Certificate not found',
          code: 'CERT_NOT_FOUND'
        };
      }

      // Perform comprehensive verification
      const verificationResult = await this.performFullVerification(certificate);
      
      // Update statistics
      await certificate.incrementStats('verification');

      return verificationResult;

    } catch (error) {
      return {
        valid: false,
        error: `Verification failed: ${error.message}`,
        code: 'VERIFICATION_ERROR'
      };
    }
  }

  /**
   * Perform full certificate verification
   * @param {Object} certificate - Certificate document
   * @returns {Promise<Object>} - Verification result
   */
  async performFullVerification(certificate) {
    const verificationChecks = [];
    let overallValid = true;

    // 1. Basic validity check
    const basicCheck = this.checkBasicValidity(certificate);
    verificationChecks.push({
      check: 'basic_validity',
      passed: basicCheck.valid,
      message: basicCheck.message,
      details: basicCheck.details
    });
    if (!basicCheck.valid) overallValid = false;

    // 2. Digital signature verification
    const signatureCheck = await this.verifyDigitalSignature(certificate);
    verificationChecks.push({
      check: 'digital_signature',
      passed: signatureCheck.valid,
      message: signatureCheck.message,
      details: signatureCheck.details
    });
    if (!signatureCheck.valid) overallValid = false;

    // 3. Integrity verification
    const integrityCheck = this.verifyIntegrity(certificate);
    verificationChecks.push({
      check: 'data_integrity',
      passed: integrityCheck.valid,
      message: integrityCheck.message,
      details: integrityCheck.details
    });
    if (!integrityCheck.valid) overallValid = false;

    // 4. Compliance verification
    const complianceCheck = this.verifyCompliance(certificate);
    verificationChecks.push({
      check: 'compliance',
      passed: complianceCheck.valid,
      message: complianceCheck.message,
      details: complianceCheck.details
    });
    if (!complianceCheck.valid) overallValid = false;

    // 5. Temporal validity
    const temporalCheck = this.checkTemporalValidity(certificate);
    verificationChecks.push({
      check: 'temporal_validity',
      passed: temporalCheck.valid,
      message: temporalCheck.message,
      details: temporalCheck.details
    });
    if (!temporalCheck.valid) overallValid = false;

    // 6. Authority verification
    const authorityCheck = this.verifyIssuingAuthority(certificate);
    verificationChecks.push({
      check: 'issuing_authority',
      passed: authorityCheck.valid,
      message: authorityCheck.message,
      details: authorityCheck.details
    });
    if (!authorityCheck.valid) overallValid = false;

    // 7. Third-party verification (if required)
    let thirdPartyCheck = null;
    if (certificate.verification?.thirdParty?.required) {
      thirdPartyCheck = await this.performThirdPartyVerification(certificate);
      verificationChecks.push({
        check: 'third_party_verification',
        passed: thirdPartyCheck.valid,
        message: thirdPartyCheck.message,
        details: thirdPartyCheck.details
      });
      if (!thirdPartyCheck.valid) overallValid = false;
    }

    // 8. Revocation check
    const revocationCheck = await this.checkRevocationStatus(certificate);
    verificationChecks.push({
      check: 'revocation_status',
      passed: revocationCheck.valid,
      message: revocationCheck.message,
      details: revocationCheck.details
    });
    if (!revocationCheck.valid) overallValid = false;

    // Generate verification summary
    const summary = this.generateVerificationSummary(certificate, verificationChecks, overallValid);

    return {
      valid: overallValid,
      certificateId: certificate.certificateId,
      summary,
      checks: verificationChecks,
      verifiedAt: new Date().toISOString(),
      verificationId: this.generateVerificationId(),
      compliance: {
        standard: certificate.compliance?.standard || 'NIST_SP_800_88',
        level: this.determineComplianceLevel(verificationChecks)
      }
    };
  }

  /**
   * Check basic certificate validity
   * @param {Object} certificate - Certificate document
   * @returns {Object} - Basic validity result
   */
  checkBasicValidity(certificate) {
    const checks = [];
    let valid = true;

    // Required fields check
    const requiredFields = [
      'certificateId', 'device', 'wipeRecord', 'deviceInfo',
      'compliance', 'technician', 'verification'
    ];

    for (const field of requiredFields) {
      if (!certificate[field]) {
        checks.push(`Missing required field: ${field}`);
        valid = false;
      }
    }

    // Certificate ID format check
    if (certificate.certificateId && !certificate.certificateId.match(/^CERT-[A-Z0-9]+-[A-F0-9]+$/)) {
      checks.push('Invalid certificate ID format');
      valid = false;
    }

    // Status check
    if (certificate.status === 'revoked') {
      checks.push('Certificate has been revoked');
      valid = false;
    }

    return {
      valid,
      message: valid ? 'Basic validity checks passed' : 'Basic validity checks failed',
      details: checks
    };
  }

  /**
   * Verify digital signature
   * @param {Object} certificate - Certificate document
   * @returns {Promise<Object>} - Signature verification result
   */
  async verifyDigitalSignature(certificate) {
    try {
      if (!certificate.digitalSignature || !certificate.digitalSignature.signature) {
        return {
          valid: false,
          message: 'No digital signature found',
          details: ['Certificate does not contain a digital signature']
        };
      }

      const signature = certificate.digitalSignature;
      
      // Recreate the content that was signed
      const signedContent = JSON.stringify({
        certificateId: certificate.certificateId,
        wipeRecord: certificate.wipeRecord,
        deviceInfo: certificate.deviceInfo,
        compliance: certificate.compliance,
        verification: certificate.verification,
        timestamp: signature.timestamp
      });

      // Verify using the public key
      try {
        const publicKey = forge.pki.publicKeyFromPem(signature.publicKey);
        const signatureBytes = forge.util.decode64(signature.signature);
        
        const md = forge.md.sha256.create();
        md.update(signedContent, 'utf8');
        
        const isValid = publicKey.verify(md.digest().bytes(), signatureBytes);
        
        if (isValid) {
          return {
            valid: true,
            message: 'Digital signature is valid',
            details: [
              `Algorithm: ${signature.algorithm}`,
              `Signed at: ${signature.timestamp}`,
              `Issuer: ${signature.issuer}`
            ]
          };
        } else {
          return {
            valid: false,
            message: 'Digital signature verification failed',
            details: ['Signature does not match certificate content']
          };
        }
      } catch (error) {
        return {
          valid: false,
          message: 'Digital signature verification error',
          details: [`Verification error: ${error.message}`]
        };
      }

    } catch (error) {
      return {
        valid: false,
        message: 'Digital signature verification failed',
        details: [`Error: ${error.message}`]
      };
    }
  }

  /**
   * Verify certificate integrity
   * @param {Object} certificate - Certificate document
   * @returns {Object} - Integrity verification result
   */
  verifyIntegrity(certificate) {
    try {
      if (!certificate.integrity || !certificate.integrity.hash) {
        return {
          valid: false,
          message: 'No integrity hash found',
          details: ['Certificate does not contain integrity verification data']
        };
      }

      // Recreate content hash
      const content = {
        certificateId: certificate.certificateId,
        device: certificate.device,
        wipeRecord: certificate.wipeRecord,
        deviceInfo: certificate.deviceInfo,
        compliance: certificate.compliance,
        technician: certificate.technician,
        verification: certificate.verification,
        digitalSignature: certificate.digitalSignature,
        metadata: certificate.metadata
      };

      const contentString = JSON.stringify(content) + (certificate.integrity.salt || '');
      const calculatedHash = crypto.createHash('sha256').update(contentString).digest('hex');

      const isValid = calculatedHash === certificate.integrity.hash;

      return {
        valid: isValid,
        message: isValid ? 'Certificate integrity verified' : 'Certificate integrity check failed',
        details: isValid ? 
          ['Content hash matches stored hash'] : 
          ['Content hash does not match - certificate may have been tampered with']
      };

    } catch (error) {
      return {
        valid: false,
        message: 'Integrity verification failed',
        details: [`Error: ${error.message}`]
      };
    }
  }

  /**
   * Verify NIST compliance
   * @param {Object} certificate - Certificate document
   * @returns {Object} - Compliance verification result
   */
  verifyCompliance(certificate) {
    const checks = [];
    let valid = true;

    // Check compliance standard
    const supportedStandards = ['NIST_SP_800_88', 'DoD_5220_22_M', 'CESG_HMG_IA_5'];
    if (!supportedStandards.includes(certificate.compliance?.standard)) {
      checks.push(`Unsupported compliance standard: ${certificate.compliance?.standard}`);
      valid = false;
    }

    // Check wipe method compliance
    const nistMethods = ['nist_clear', 'nist_purge', 'dod_3pass', 'dod_7pass', 'gutmann'];
    if (!nistMethods.includes(certificate.wipeRecord?.method)) {
      checks.push(`Non-compliant wipe method: ${certificate.wipeRecord?.method}`);
      valid = false;
    }

    // Check verification requirements
    if (!certificate.verification?.automated?.checksum) {
      checks.push('Missing automated verification checksum');
      valid = false;
    }

    // Check minimum verification rate
    const verificationRate = certificate.verification?.automated?.passRate || 0;
    if (verificationRate < 95) {
      checks.push(`Insufficient verification rate: ${verificationRate}% (minimum 95%)`);
      valid = false;
    }

    return {
      valid,
      message: valid ? 'Compliance requirements met' : 'Compliance requirements not met',
      details: valid ? 
        [`Standard: ${certificate.compliance?.standard}`, `Method: ${certificate.wipeRecord?.method}`] :
        checks
    };
  }

  /**
   * Check temporal validity
   * @param {Object} certificate - Certificate document
   * @returns {Object} - Temporal validity result
   */
  checkTemporalValidity(certificate) {
    const now = moment();
    const validFrom = moment(certificate.metadata?.validFrom);
    const validUntil = moment(certificate.metadata?.validUntil);

    const checks = [];
    let valid = true;

    if (!validFrom.isValid()) {
      checks.push('Invalid validFrom date');
      valid = false;
    }

    if (!validUntil.isValid()) {
      checks.push('Invalid validUntil date');
      valid = false;
    }

    if (valid) {
      if (now.isBefore(validFrom)) {
        checks.push('Certificate is not yet valid');
        valid = false;
      }

      if (now.isAfter(validUntil)) {
        checks.push('Certificate has expired');
        valid = false;
      }
    }

    return {
      valid,
      message: valid ? 'Certificate is within valid time period' : 'Certificate temporal validity failed',
      details: valid ? 
        [
          `Valid from: ${validFrom.format('YYYY-MM-DD HH:mm:ss')} UTC`,
          `Valid until: ${validUntil.format('YYYY-MM-DD HH:mm:ss')} UTC`,
          `Days remaining: ${validUntil.diff(now, 'days')}`
        ] : 
        checks
    };
  }

  /**
   * Verify issuing authority
   * @param {Object} certificate - Certificate document
   * @returns {Object} - Authority verification result
   */
  verifyIssuingAuthority(certificate) {
    const issuer = certificate.metadata?.issuer?.name || certificate.digitalSignature?.issuer;
    
    if (!issuer) {
      return {
        valid: false,
        message: 'No issuing authority information found',
        details: ['Certificate does not contain issuer information']
      };
    }

    const isTrusted = this.trustedAuthorities.includes(issuer);

    return {
      valid: isTrusted,
      message: isTrusted ? 'Issuing authority is trusted' : 'Issuing authority is not trusted',
      details: [
        `Issuer: ${issuer}`,
        `Trusted: ${isTrusted ? 'Yes' : 'No'}`,
        `Organization: ${certificate.metadata?.issuer?.organization || 'Unknown'}`
      ]
    };
  }

  /**
   * Perform third-party verification
   * @param {Object} certificate - Certificate document
   * @returns {Promise<Object>} - Third-party verification result
   */
  async performThirdPartyVerification(certificate) {
    try {
      if (!this.verificationEndpoint || !this.apiKey) {
        return {
          valid: false,
          message: 'Third-party verification not configured',
          details: ['No verification endpoint or API key configured']
        };
      }

      const verificationRequest = {
        certificateId: certificate.certificateId,
        deviceInfo: certificate.deviceInfo,
        wipeRecord: certificate.wipeRecord,
        compliance: certificate.compliance,
        requestedAt: new Date().toISOString()
      };

      const response = await axios.post(`${this.verificationEndpoint}/api/verify`, 
        verificationRequest,
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 30000 // 30 seconds timeout
        }
      );

      if (response.data.verified) {
        return {
          valid: true,
          message: 'Third-party verification successful',
          details: [
            `Verification ID: ${response.data.verificationId}`,
            `Verified by: ${response.data.verifier}`,
            `Verification time: ${response.data.verifiedAt}`
          ]
        };
      } else {
        return {
          valid: false,
          message: 'Third-party verification failed',
          details: response.data.errors || ['Verification rejected by third party']
        };
      }

    } catch (error) {
      return {
        valid: false,
        message: 'Third-party verification error',
        details: [`Unable to contact verification service: ${error.message}`]
      };
    }
  }

  /**
   * Check revocation status
   * @param {Object} certificate - Certificate document
   * @returns {Promise<Object>} - Revocation check result
   */
  async checkRevocationStatus(certificate) {
    try {
      // Check local revocation status
      if (certificate.status === 'revoked') {
        return {
          valid: false,
          message: 'Certificate has been revoked',
          details: [
            `Revoked at: ${certificate.metadata?.revokedAt}`,
            `Reason: ${certificate.metadata?.revocationReason || 'Not specified'}`
          ]
        };
      }

      // Additional check against external CRL if configured
      // This would be implemented for production systems with external CRL endpoints
      
      return {
        valid: true,
        message: 'Certificate is not revoked',
        details: ['Certificate status: Active']
      };

    } catch (error) {
      return {
        valid: false,
        message: 'Revocation check failed',
        details: [`Error checking revocation status: ${error.message}`]
      };
    }
  }

  /**
   * Generate verification summary
   * @param {Object} certificate - Certificate document
   * @param {Array} checks - Verification checks
   * @param {boolean} overallValid - Overall validity
   * @returns {Object} - Verification summary
   */
  generateVerificationSummary(certificate, checks, overallValid) {
    const passedChecks = checks.filter(check => check.passed).length;
    const totalChecks = checks.length;

    return {
      overallValid,
      passedChecks,
      totalChecks,
      successRate: Math.round((passedChecks / totalChecks) * 100),
      certificate: {
        id: certificate.certificateId,
        device: certificate.deviceInfo?.model || 'Unknown',
        method: certificate.wipeRecord?.method,
        issuedAt: certificate.createdAt,
        expiresAt: certificate.metadata?.validUntil
      },
      recommendation: overallValid ? 
        'Certificate is valid and can be trusted' :
        'Certificate verification failed - do not trust this certificate',
      trustLevel: this.calculateTrustLevel(checks, overallValid)
    };
  }

  /**
   * Determine compliance level
   * @param {Array} checks - Verification checks
   * @returns {string} - Compliance level
   */
  determineComplianceLevel(checks) {
    const complianceCheck = checks.find(check => check.check === 'compliance');
    const signatureCheck = checks.find(check => check.check === 'digital_signature');
    const integrityCheck = checks.find(check => check.check === 'data_integrity');

    if (complianceCheck?.passed && signatureCheck?.passed && integrityCheck?.passed) {
      return 'high';
    } else if (complianceCheck?.passed && (signatureCheck?.passed || integrityCheck?.passed)) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Calculate trust level
   * @param {Array} checks - Verification checks
   * @param {boolean} overallValid - Overall validity
   * @returns {string} - Trust level
   */
  calculateTrustLevel(checks, overallValid) {
    if (!overallValid) return 'untrusted';

    const criticalChecks = ['digital_signature', 'data_integrity', 'compliance'];
    const criticalPassed = checks
      .filter(check => criticalChecks.includes(check.check))
      .every(check => check.passed);

    if (criticalPassed && checks.every(check => check.passed)) {
      return 'fully_trusted';
    } else if (criticalPassed) {
      return 'trusted';
    } else {
      return 'partially_trusted';
    }
  }

  /**
   * Generate unique verification ID
   * @returns {string} - Verification ID
   */
  generateVerificationId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    return `VER-${timestamp}-${random}`;
  }

  /**
   * Batch verify multiple certificates
   * @param {Array} certificateIds - Array of certificate IDs
   * @returns {Promise<Array>} - Array of verification results
   */
  async batchVerifyCertificates(certificateIds) {
    const results = [];
    
    for (const certificateId of certificateIds) {
      try {
        const result = await this.verifyCertificate(certificateId);
        results.push(result);
      } catch (error) {
        results.push({
          certificateId,
          valid: false,
          error: error.message,
          code: 'VERIFICATION_ERROR'
        });
      }
    }

    return results;
  }

  /**
   * Generate verification report
   * @param {string} certificateId - Certificate ID
   * @returns {Promise<Object>} - Verification report
   */
  async generateVerificationReport(certificateId) {
    const verification = await this.verifyCertificate(certificateId);
    
    return {
      report: {
        title: 'JNARDDC Certificate Verification Report',
        certificateId,
        generatedAt: new Date().toISOString(),
        verificationId: verification.verificationId,
        summary: verification.summary,
        detailedResults: verification.checks,
        conclusion: verification.valid ? 'VERIFIED' : 'FAILED',
        recommendation: verification.summary?.recommendation,
        trustLevel: verification.summary?.trustLevel
      },
      verification
    };
  }
}

module.exports = VerificationService;