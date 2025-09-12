const mongoose = require('mongoose');
const crypto = require('crypto');

const certificateSchema = new mongoose.Schema({
  certificateId: {
    type: String,
    required: [true, 'Certificate ID is required'],
    unique: true,
    trim: true
  },
  device: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Device',
    required: [true, 'Device reference is required']
  },
  wipeRecord: {
    wipeId: { type: String, required: true },
    method: {
      type: String,
      enum: ['nist_clear', 'nist_purge', 'dod_3pass', 'dod_7pass', 'gutmann', 'random_overwrite', 'crypto_erase'],
      required: true
    },
    passes: { type: Number, min: 1, max: 35 },
    startedAt: { type: Date, required: true },
    completedAt: { type: Date, required: true },
    duration: { type: Number, required: true }, // in minutes
    status: {
      type: String,
      enum: ['completed', 'completed_with_errors', 'partial'],
      required: true
    }
  },
  deviceInfo: {
    manufacturer: String,
    model: { type: String, required: true },
    serialNumber: String,
    type: { type: String, required: true },
    storageDevices: [{
      type: String,
      capacity: Number,
      model: String,
      serialNumber: String,
      sectorsWiped: Number,
      sectorsTotal: Number,
      success: Boolean
    }]
  },
  compliance: {
    standard: {
      type: String,
      enum: ['NIST_SP_800_88', 'DoD_5220_22_M', 'CESG_HMG_IA_5', 'BSI_2011_VS', 'custom'],
      required: true
    },
    version: String,
    requirements: [{
      requirement: String,
      status: { type: String, enum: ['met', 'not_met', 'not_applicable'] },
      details: String
    }],
    certificationLevel: {
      type: String,
      enum: ['basic', 'enhanced', 'high_security', 'top_secret'],
      required: true
    }
  },
  technician: {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    name: { type: String, required: true },
    email: { type: String, required: true },
    credentials: {
      certifications: [String],
      licenseNumber: String,
      organization: String
    }
  },
  verification: {
    automated: {
      checksum: { type: String, required: true },
      randomSampling: {
        sectors: [Number],
        results: [String],
        passRate: Number
      },
      timestamp: { type: Date, required: true }
    },
    thirdParty: {
      required: { type: Boolean, default: false },
      verifier: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      verifiedAt: Date,
      status: {
        type: String,
        enum: ['pending', 'verified', 'rejected', 'expired']
      },
      signature: String,
      notes: String
    }
  },
  digitalSignature: {
    algorithm: { type: String, default: 'RSA-SHA256' },
    signature: { type: String, required: true },
    publicKey: { type: String, required: true },
    certificateChain: [String],
    timestamp: { type: Date, required: true }
  },
  integrity: {
    hash: { type: String, required: true }, // SHA-256 hash of certificate content
    salt: { type: String, required: true },
    version: { type: Number, default: 1 },
    tamperProof: { type: Boolean, default: true }
  },
  documents: {
    pdf: {
      generated: { type: Boolean, default: false },
      filename: String,
      size: Number,
      checksum: String,
      path: String
    },
    json: {
      generated: { type: Boolean, default: false },
      filename: String,
      size: Number,
      checksum: String,
      content: mongoose.Schema.Types.Mixed
    },
    qrCode: {
      generated: { type: Boolean, default: false },
      data: String,
      verificationUrl: String
    }
  },
  distribution: {
    owner: {
      delivered: { type: Boolean, default: false },
      method: { type: String, enum: ['email', 'download', 'physical'] },
      deliveredAt: Date
    },
    organization: {
      delivered: { type: Boolean, default: false },
      method: { type: String, enum: ['email', 'api', 'portal'] },
      deliveredAt: Date
    },
    authorities: [{
      name: String,
      delivered: { type: Boolean, default: false },
      method: String,
      deliveredAt: Date
    }]
  },
  status: {
    type: String,
    enum: ['draft', 'issued', 'verified', 'revoked', 'expired'],
    default: 'draft'
  },
  metadata: {
    issuer: {
      name: { type: String, default: 'JNARDDC Secure Wipe Authority' },
      country: { type: String, default: 'India' },
      organization: { type: String, default: 'Ministry of Mines' },
      department: { type: String, default: 'Jawaharlal Nehru Aluminium Research Development and Design Centre' }
    },
    validFrom: { type: Date, required: true },
    validUntil: { type: Date, required: true },
    revocationReason: String,
    revokedAt: Date,
    auditTrail: [{
      action: String,
      performedBy: String,
      timestamp: { type: Date, default: Date.now },
      details: String
    }]
  },
  statistics: {
    viewCount: { type: Number, default: 0 },
    downloadCount: { type: Number, default: 0 },
    verificationCount: { type: Number, default: 0 },
    lastAccessed: Date
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Don't expose sensitive fields in JSON
      delete ret.digitalSignature.signature;
      delete ret.integrity.salt;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual for certificate validity
certificateSchema.virtual('isValid').get(function() {
  const now = new Date();
  return this.status === 'issued' && 
         now >= this.metadata.validFrom && 
         now <= this.metadata.validUntil;
});

// Virtual for days until expiry
certificateSchema.virtual('daysUntilExpiry').get(function() {
  const now = new Date();
  const expiry = new Date(this.metadata.validUntil);
  return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
});

// Virtual for verification URL
certificateSchema.virtual('verificationUrl').get(function() {
  return `${process.env.VERIFICATION_BASE_URL || 'https://verify.jnarddc.gov.in'}/certificate/${this.certificateId}`;
});

// Indexes for performance
certificateSchema.index({ certificateId: 1 });
certificateSchema.index({ device: 1 });
certificateSchema.index({ 'technician.userId': 1 });
certificateSchema.index({ status: 1 });
certificateSchema.index({ createdAt: -1 });
certificateSchema.index({ 'metadata.validUntil': 1 });
certificateSchema.index({ 'wipeRecord.completedAt': -1 });

// Text index for search
certificateSchema.index({
  certificateId: 'text',
  'deviceInfo.model': 'text',
  'deviceInfo.manufacturer': 'text',
  'technician.name': 'text'
});

// Pre-save middleware
certificateSchema.pre('save', function(next) {
  // Generate certificate ID if not provided
  if (this.isNew && !this.certificateId) {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    this.certificateId = `CERT-${timestamp}-${random}`;
  }

  // Set validity period (5 years by default)
  if (this.isNew && !this.metadata.validUntil) {
    this.metadata.validFrom = new Date();
    this.metadata.validUntil = new Date(Date.now() + (5 * 365 * 24 * 60 * 60 * 1000));
  }

  // Generate integrity hash
  this.generateIntegrityHash();
  
  next();
});

// Instance methods
certificateSchema.methods.generateIntegrityHash = function() {
  // Generate salt if not exists
  if (!this.integrity.salt) {
    this.integrity.salt = crypto.randomBytes(32).toString('hex');
  }

  // Create content for hashing (excluding the hash itself)
  const content = {
    certificateId: this.certificateId,
    device: this.device,
    wipeRecord: this.wipeRecord,
    deviceInfo: this.deviceInfo,
    compliance: this.compliance,
    technician: this.technician,
    verification: this.verification,
    digitalSignature: this.digitalSignature,
    metadata: this.metadata
  };

  // Generate hash
  const contentString = JSON.stringify(content) + this.integrity.salt;
  this.integrity.hash = crypto.createHash('sha256').update(contentString).digest('hex');
  
  return this.integrity.hash;
};

certificateSchema.methods.verifyIntegrity = function() {
  const currentHash = this.integrity.hash;
  const calculatedHash = this.generateIntegrityHash();
  return currentHash === calculatedHash;
};

certificateSchema.methods.addAuditEntry = function(action, performedBy, details = '') {
  this.metadata.auditTrail.push({
    action,
    performedBy,
    timestamp: new Date(),
    details
  });
  return this.save();
};

certificateSchema.methods.revoke = function(reason, revokedBy) {
  this.status = 'revoked';
  this.metadata.revocationReason = reason;
  this.metadata.revokedAt = new Date();
  
  return this.addAuditEntry('revoked', revokedBy, reason);
};

certificateSchema.methods.signCertificate = async function(privateKey, algorithm = 'RSA-SHA256') {
  const content = this.generateSignatureContent();
  
  // Create signature
  const sign = crypto.createSign(algorithm);
  sign.update(content);
  
  this.digitalSignature = {
    algorithm,
    signature: sign.sign(privateKey, 'hex'),
    publicKey: this.extractPublicKey(privateKey),
    timestamp: new Date()
  };
  
  return this.save();
};

certificateSchema.methods.verifySignature = function() {
  if (!this.digitalSignature.signature) {
    return false;
  }

  try {
    const content = this.generateSignatureContent();
    const verify = crypto.createVerify(this.digitalSignature.algorithm);
    verify.update(content);
    
    return verify.verify(this.digitalSignature.publicKey, this.digitalSignature.signature, 'hex');
  } catch (error) {
    return false;
  }
};

certificateSchema.methods.generateSignatureContent = function() {
  // Content to be signed (excluding signature itself)
  return JSON.stringify({
    certificateId: this.certificateId,
    wipeRecord: this.wipeRecord,
    deviceInfo: this.deviceInfo,
    compliance: this.compliance,
    verification: this.verification,
    timestamp: this.digitalSignature.timestamp || this.createdAt
  });
};

certificateSchema.methods.extractPublicKey = function(privateKey) {
  // This is a simplified version - in production, use proper key management
  try {
    const keyObject = crypto.createPrivateKey(privateKey);
    return crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'pem' });
  } catch (error) {
    throw new Error('Failed to extract public key');
  }
};

certificateSchema.methods.incrementStats = function(type) {
  if (type === 'view') {
    this.statistics.viewCount += 1;
  } else if (type === 'download') {
    this.statistics.downloadCount += 1;
  } else if (type === 'verification') {
    this.statistics.verificationCount += 1;
  }
  
  this.statistics.lastAccessed = new Date();
  return this.save();
};

// Static methods
certificateSchema.statics.findByDeviceId = function(deviceId) {
  return this.find({})
    .populate({
      path: 'device',
      match: { deviceId: deviceId },
      select: 'deviceId deviceInfo status'
    })
    .populate('technician.userId', 'username email profile.firstName profile.lastName')
    .sort({ createdAt: -1 });
};

certificateSchema.statics.findExpiring = function(days = 30) {
  const futureDate = new Date(Date.now() + (days * 24 * 60 * 60 * 1000));
  return this.find({
    status: 'issued',
    'metadata.validUntil': { $lte: futureDate, $gte: new Date() }
  })
  .populate('device', 'deviceId deviceInfo')
  .sort({ 'metadata.validUntil': 1 });
};

certificateSchema.statics.getCertificateStatistics = function() {
  return this.aggregate([
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 }
      }
    },
    {
      $group: {
        _id: null,
        statusBreakdown: {
          $push: {
            status: '$_id',
            count: '$count'
          }
        },
        totalCertificates: { $sum: '$count' }
      }
    }
  ]);
};

certificateSchema.statics.verifyById = async function(certificateId) {
  const certificate = await this.findOne({ certificateId });
  
  if (!certificate) {
    throw new Error('Certificate not found');
  }
  
  // Verify integrity and signature
  const integrityValid = certificate.verifyIntegrity();
  const signatureValid = certificate.verifySignature();
  
  // Update statistics
  await certificate.incrementStats('verification');
  
  return {
    certificate,
    verification: {
      integrityValid,
      signatureValid,
      isValid: certificate.isValid,
      status: certificate.status
    }
  };
};

module.exports = mongoose.model('Certificate', certificateSchema);