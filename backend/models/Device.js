const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  deviceId: {
    type: String,
    required: [true, 'Device ID is required'],
    unique: true,
    trim: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Device owner is required']
  },
  deviceInfo: {
    manufacturer: { type: String, trim: true },
    model: { type: String, required: [true, 'Device model is required'], trim: true },
    serialNumber: { type: String, unique: true, sparse: true, trim: true },
    type: {
      type: String,
      required: [true, 'Device type is required'],
      enum: ['laptop', 'desktop', 'smartphone', 'tablet', 'server', 'hard_drive', 'ssd', 'other']
    },
    category: {
      type: String,
      enum: ['personal', 'corporate', 'government', 'educational'],
      default: 'personal'
    }
  },
  hardware: {
    cpu: {
      manufacturer: String,
      model: String,
      cores: Number,
      architecture: { type: String, enum: ['x86', 'x64', 'ARM', 'ARM64', 'other'] }
    },
    memory: {
      total: Number, // in GB
      type: { type: String, enum: ['DDR3', 'DDR4', 'DDR5', 'LPDDR4', 'LPDDR5', 'other'] }
    },
    storage: [{
      type: { type: String, enum: ['HDD', 'SSD', 'NVMe', 'eMMC', 'SD', 'other'], required: true },
      capacity: { type: Number, required: true }, // in GB
      interface: { type: String, enum: ['SATA', 'NVMe', 'PCIe', 'USB', 'eMMC', 'other'] },
      model: String,
      serialNumber: String,
      firmware: String,
      partitions: [{
        number: Number,
        type: String,
        filesystem: String,
        size: Number, // in GB
        mountPoint: String
      }]
    }],
    networking: {
      hasWifi: { type: Boolean, default: false },
      hasEthernet: { type: Boolean, default: false },
      hasBluetooth: { type: Boolean, default: false },
      hasCellular: { type: Boolean, default: false }
    }
  },
  operatingSystem: {
    name: { type: String, enum: ['Windows', 'Linux', 'macOS', 'Android', 'iOS', 'other'] },
    version: String,
    build: String,
    architecture: { type: String, enum: ['32-bit', '64-bit', 'ARM', 'ARM64'] },
    lastUpdated: Date
  },
  security: {
    encryptionStatus: {
      type: String,
      enum: ['none', 'partial', 'full', 'unknown'],
      default: 'unknown'
    },
    encryptionType: { type: String, enum: ['BitLocker', 'FileVault', 'LUKS', 'dm-crypt', 'other'] },
    tpmVersion: String,
    secureBootEnabled: { type: Boolean, default: false },
    biosPassword: { type: Boolean, default: false },
    lastSecurityScan: Date
  },
  status: {
    current: {
      type: String,
      enum: ['registered', 'ready_for_wipe', 'wiping_in_progress', 'wipe_completed', 'wipe_failed', 'verified', 'recycled'],
      default: 'registered'
    },
    lastUpdated: { type: Date, default: Date.now },
    notes: String
  },
  wipeHistory: [{
    wipeId: { type: String, required: true },
    startedAt: { type: Date, required: true },
    completedAt: Date,
    status: {
      type: String,
      enum: ['in_progress', 'completed', 'failed', 'cancelled'],
      required: true
    },
    method: {
      type: String,
      enum: ['nist_clear', 'nist_purge', 'dod_3pass', 'dod_7pass', 'gutmann', 'random_overwrite', 'crypto_erase'],
      required: true
    },
    passes: { type: Number, min: 1, max: 35 },
    sectors: {
      total: Number,
      wiped: Number,
      failed: Number,
      verified: Number
    },
    certificate: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Certificate'
    },
    technician: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    errors: [String],
    logs: String, // Path to detailed log file
    duration: Number, // in minutes
    throughput: Number // MB/s average
  }],
  compliance: {
    standard: {
      type: String,
      enum: ['NIST_SP_800_88', 'DoD_5220_22_M', 'CESG_HMG_IA_5', 'BSI_2011_VS', 'custom'],
      default: 'NIST_SP_800_88'
    },
    requirements: [String],
    certificationLevel: {
      type: String,
      enum: ['basic', 'enhanced', 'high_security', 'top_secret']
    }
  },
  verification: {
    required: { type: Boolean, default: true },
    thirdParty: {
      enabled: { type: Boolean, default: false },
      verifier: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      verifiedAt: Date,
      status: {
        type: String,
        enum: ['pending', 'verified', 'rejected', 'expired']
      },
      notes: String
    },
    automated: {
      checksum: String,
      randomSampling: {
        sectors: [Number],
        results: [String]
      },
      lastVerified: Date
    }
  },
  recycling: {
    scheduledDate: Date,
    recycler: {
      name: String,
      licenseNumber: String,
      contactInfo: {
        email: String,
        phone: String,
        address: String
      }
    },
    trackingNumber: String,
    certificateProvided: { type: Boolean, default: false },
    completedAt: Date
  },
  location: {
    facility: String,
    building: String,
    floor: String,
    room: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    }
  },
  tags: [String],
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  estimatedValue: Number, // in INR
  isActive: { type: Boolean, default: true }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for device age
deviceSchema.virtual('age').get(function() {
  if (!this.createdAt) return null;
  const now = new Date();
  const created = new Date(this.createdAt);
  return Math.floor((now - created) / (1000 * 60 * 60 * 24)); // days
});

// Virtual for last wipe info
deviceSchema.virtual('lastWipe').get(function() {
  if (!this.wipeHistory || this.wipeHistory.length === 0) return null;
  return this.wipeHistory[this.wipeHistory.length - 1];
});

// Virtual for total storage capacity
deviceSchema.virtual('totalStorage').get(function() {
  if (!this.hardware.storage || this.hardware.storage.length === 0) return 0;
  return this.hardware.storage.reduce((total, storage) => total + (storage.capacity || 0), 0);
});

// Indexes for performance
deviceSchema.index({ deviceId: 1 });
deviceSchema.index({ owner: 1 });
deviceSchema.index({ 'deviceInfo.type': 1 });
deviceSchema.index({ 'status.current': 1 });
deviceSchema.index({ createdAt: -1 });
deviceSchema.index({ 'wipeHistory.completedAt': -1 });
deviceSchema.index({ 'recycling.scheduledDate': 1 });

// Text index for search
deviceSchema.index({
  'deviceInfo.model': 'text',
  'deviceInfo.manufacturer': 'text',
  'deviceInfo.serialNumber': 'text',
  tags: 'text'
});

// Pre-save middleware
deviceSchema.pre('save', function(next) {
  // Update status timestamp when status changes
  if (this.isModified('status.current')) {
    this.status.lastUpdated = new Date();
  }
  
  // Generate device ID if not provided
  if (this.isNew && !this.deviceId) {
    const crypto = require('crypto');
    this.deviceId = `DEV-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  }
  
  next();
});

// Instance methods
deviceSchema.methods.addWipeRecord = function(wipeData) {
  this.wipeHistory.push(wipeData);
  
  // Update device status based on wipe status
  if (wipeData.status === 'completed') {
    this.status.current = 'wipe_completed';
  } else if (wipeData.status === 'failed') {
    this.status.current = 'wipe_failed';
  } else if (wipeData.status === 'in_progress') {
    this.status.current = 'wiping_in_progress';
  }
  
  return this.save();
};

deviceSchema.methods.updateHardwareInfo = function(hardwareData) {
  this.hardware = { ...this.hardware.toObject(), ...hardwareData };
  return this.save();
};

deviceSchema.methods.scheduleRecycling = function(recyclingData) {
  this.recycling = { ...this.recycling.toObject(), ...recyclingData };
  return this.save();
};

// Static methods
deviceSchema.statics.findByStatus = function(status) {
  return this.find({ 'status.current': status, isActive: true })
    .populate('owner', 'username email profile.firstName profile.lastName')
    .populate('wipeHistory.certificate', 'certificateId status')
    .sort({ 'status.lastUpdated': -1 });
};

deviceSchema.statics.findPendingWipes = function() {
  return this.find({
    'status.current': { $in: ['ready_for_wipe', 'wiping_in_progress'] },
    isActive: true
  })
  .populate('owner', 'username email profile.firstName profile.lastName')
  .sort({ priority: 1, createdAt: 1 });
};

deviceSchema.statics.getWipeStatistics = function() {
  return this.aggregate([
    { $match: { isActive: true } },
    {
      $group: {
        _id: '$status.current',
        count: { $sum: 1 },
        totalValue: { $sum: '$estimatedValue' }
      }
    },
    {
      $group: {
        _id: null,
        statusBreakdown: {
          $push: {
            status: '$_id',
            count: '$count',
            value: '$totalValue'
          }
        },
        totalDevices: { $sum: '$count' },
        totalValue: { $sum: '$totalValue' }
      }
    }
  ]);
};

module.exports = mongoose.model('Device', deviceSchema);