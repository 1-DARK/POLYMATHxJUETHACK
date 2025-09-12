const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false // Don't include password in query results by default
  },
  role: {
    type: String,
    enum: ['user', 'technician', 'administrator', 'verifier'],
    default: 'user'
  },
  organization: {
    name: { type: String, trim: true },
    department: { type: String, trim: true },
    employeeId: { type: String, trim: true }
  },
  profile: {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    phoneNumber: { 
      type: String, 
      match: [/^[6-9]\d{9}$/, 'Please enter a valid Indian phone number']
    },
    address: {
      street: String,
      city: String,
      state: String,
      pincode: { 
        type: String, 
        match: [/^[1-9][0-9]{5}$/, 'Please enter a valid Indian pincode']
      }
    }
  },
  preferences: {
    language: { type: String, default: 'en', enum: ['en', 'hi'] },
    notifications: { type: Boolean, default: true },
    theme: { type: String, default: 'light', enum: ['light', 'dark'] }
  },
  security: {
    twoFactorEnabled: { type: Boolean, default: false },
    lastLogin: Date,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
    passwordChangedAt: { type: Date, default: Date.now },
    apiKeys: [{
      name: String,
      key: String,
      permissions: [String],
      createdAt: { type: Date, default: Date.now },
      lastUsed: Date,
      active: { type: Boolean, default: true }
    }]
  },
  certificates: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Certificate'
  }],
  devices: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Device'
  }],
  isActive: { type: Boolean, default: true },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  passwordResetToken: String,
  passwordResetExpires: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.profile.firstName} ${this.profile.lastName}`;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ 'organization.name': 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

// Instance method to increment login attempts
userSchema.methods.incLoginAttempts = async function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.security.lockUntil && this.security.lockUntil < Date.now()) {
    return await this.updateOne({
      $unset: { 'security.lockUntil': 1 },
      $set: { 'security.loginAttempts': 1 }
    });
  }
  
  const updates = { $inc: { 'security.loginAttempts': 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.security.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { 'security.lockUntil': Date.now() + 2 * 60 * 60 * 1000 };
  }
  
  return await this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  return await this.updateOne({
    $unset: { 'security.loginAttempts': 1, 'security.lockUntil': 1 }
  });
};

// Instance method to generate API key
userSchema.methods.generateApiKey = function(name, permissions = []) {
  const crypto = require('crypto');
  const apiKey = {
    name,
    key: crypto.randomBytes(32).toString('hex'),
    permissions,
    createdAt: new Date(),
    active: true
  };
  
  this.security.apiKeys.push(apiKey);
  return apiKey;
};

// Static method to find by credentials
userSchema.statics.findByCredentials = async function(email, password) {
  const user = await this.findOne({ email, isActive: true }).select('+password');
  
  if (!user || user.isLocked) {
    throw new Error('Invalid credentials');
  }
  
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    await user.incLoginAttempts();
    throw new Error('Invalid credentials');
  }
  
  // Reset login attempts on successful login
  if (user.security.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }
  
  // Update last login
  user.security.lastLogin = new Date();
  await user.save();
  
  return user;
};

// Static method for secure user lookup
userSchema.statics.findSecure = function(query, selectFields = '') {
  return this.findOne(query)
    .select(`-password -emailVerificationToken -passwordResetToken ${selectFields}`)
    .populate('certificates', 'certificateId status createdAt')
    .populate('devices', 'deviceId model status lastWipe');
};

module.exports = mongoose.model('User', userSchema);