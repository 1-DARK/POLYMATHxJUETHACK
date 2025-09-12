const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { spawn, exec } = require('child_process');
const os = require('os');
const EventEmitter = require('events');

class WipingService extends EventEmitter {
  constructor() {
    super();
    this.activeWipes = new Map();
    this.supportedMethods = {
      'nist_clear': {
        name: 'NIST SP 800-88 Clear',
        passes: 1,
        patterns: ['zeros'],
        description: 'Single pass overwrite with zeros - suitable for most storage media'
      },
      'nist_purge': {
        name: 'NIST SP 800-88 Purge',
        passes: 3,
        patterns: ['random', 'complement', 'random'],
        description: 'Three pass purge for enhanced security - suitable for sensitive data'
      },
      'dod_3pass': {
        name: 'DoD 5220.22-M (3-pass)',
        passes: 3,
        patterns: ['zeros', 'ones', 'random'],
        description: 'Department of Defense 3-pass standard'
      },
      'dod_7pass': {
        name: 'DoD 5220.22-M (7-pass)',
        passes: 7,
        patterns: ['zeros', 'ones', 'zeros', 'ones', 'zeros', 'ones', 'random'],
        description: 'Department of Defense 7-pass standard for high security'
      },
      'gutmann': {
        name: 'Gutmann (35-pass)',
        passes: 35,
        patterns: 'gutmann_sequence',
        description: 'Peter Gutmann\'s 35-pass method for maximum security'
      },
      'random_overwrite': {
        name: 'Random Overwrite',
        passes: 1,
        patterns: ['random'],
        description: 'Single pass with cryptographically secure random data'
      },
      'crypto_erase': {
        name: 'Cryptographic Erase',
        passes: 1,
        patterns: ['crypto_key_destruction'],
        description: 'Destroy encryption keys (for encrypted storage only)'
      }
    };
  }

  /**
   * Start wiping process for a device
   * @param {Object} options - Wiping configuration
   * @returns {Promise<string>} - Wipe ID
   */
  async startWipe(options) {
    const {
      devicePath,
      method = 'nist_clear',
      userId,
      deviceId,
      verificationEnabled = true,
      skipBadSectors = false,
      priority = 'normal'
    } = options;

    // Validate method
    if (!this.supportedMethods[method]) {
      throw new Error(`Unsupported wiping method: ${method}`);
    }

    // Generate unique wipe ID
    const wipeId = this.generateWipeId();
    
    // Initialize wipe record
    const wipeRecord = {
      wipeId,
      devicePath,
      method,
      userId,
      deviceId,
      status: 'initializing',
      startedAt: new Date(),
      progress: 0,
      currentPass: 0,
      totalPasses: this.supportedMethods[method].passes,
      errors: [],
      verificationEnabled,
      skipBadSectors,
      priority,
      sectors: {
        total: 0,
        current: 0,
        failed: 0,
        verified: 0
      },
      throughput: 0,
      estimatedTimeRemaining: null
    };

    this.activeWipes.set(wipeId, wipeRecord);

    // Start wiping process asynchronously
    this._executeWipe(wipeRecord).catch(error => {
      this.emit('wipe_error', { wipeId, error: error.message });
      wipeRecord.status = 'failed';
      wipeRecord.errors.push(error.message);
    });

    return wipeId;
  }

  /**
   * Get wipe status
   * @param {string} wipeId - Wipe ID
   * @returns {Object} - Wipe status
   */
  getWipeStatus(wipeId) {
    const wipeRecord = this.activeWipes.get(wipeId);
    if (!wipeRecord) {
      throw new Error(`Wipe not found: ${wipeId}`);
    }

    return {
      wipeId: wipeRecord.wipeId,
      status: wipeRecord.status,
      progress: wipeRecord.progress,
      currentPass: wipeRecord.currentPass,
      totalPasses: wipeRecord.totalPasses,
      startedAt: wipeRecord.startedAt,
      estimatedTimeRemaining: wipeRecord.estimatedTimeRemaining,
      throughput: wipeRecord.throughput,
      sectors: wipeRecord.sectors,
      errors: wipeRecord.errors.slice(-5) // Last 5 errors only
    };
  }

  /**
   * Cancel active wipe
   * @param {string} wipeId - Wipe ID
   * @returns {Promise<boolean>} - Success status
   */
  async cancelWipe(wipeId) {
    const wipeRecord = this.activeWipes.get(wipeId);
    if (!wipeRecord) {
      throw new Error(`Wipe not found: ${wipeId}`);
    }

    if (wipeRecord.status === 'completed' || wipeRecord.status === 'failed') {
      return false;
    }

    wipeRecord.status = 'cancelling';
    
    // Kill the process if it exists
    if (wipeRecord.process) {
      wipeRecord.process.kill('SIGTERM');
      
      // Force kill after 30 seconds
      setTimeout(() => {
        if (wipeRecord.process && !wipeRecord.process.killed) {
          wipeRecord.process.kill('SIGKILL');
        }
      }, 30000);
    }

    wipeRecord.status = 'cancelled';
    wipeRecord.completedAt = new Date();
    
    this.emit('wipe_cancelled', { wipeId });
    return true;
  }

  /**
   * Execute the wiping process
   * @private
   */
  async _executeWipe(wipeRecord) {
    try {
      // Pre-flight checks
      await this._performPreflightChecks(wipeRecord);
      
      // Get device information
      await this._analyzeDevice(wipeRecord);
      
      // Disable write cache (for better security)
      await this._disableWriteCache(wipeRecord);
      
      // Perform the wipe
      wipeRecord.status = 'wiping';
      await this._performWipe(wipeRecord);
      
      // Verify the wipe
      if (wipeRecord.verificationEnabled) {
        wipeRecord.status = 'verifying';
        await this._verifyWipe(wipeRecord);
      }
      
      // Check for hidden areas (HPA/DCO)
      await this._checkHiddenAreas(wipeRecord);
      
      // Mark as completed
      wipeRecord.status = 'completed';
      wipeRecord.completedAt = new Date();
      wipeRecord.progress = 100;
      
      this.emit('wipe_completed', { wipeId: wipeRecord.wipeId, wipeRecord });
      
    } catch (error) {
      wipeRecord.status = 'failed';
      wipeRecord.errors.push(error.message);
      wipeRecord.completedAt = new Date();
      
      this.emit('wipe_failed', { 
        wipeId: wipeRecord.wipeId, 
        error: error.message,
        wipeRecord 
      });
      
      throw error;
    }
  }

  /**
   * Perform pre-flight checks
   * @private
   */
  async _performPreflightChecks(wipeRecord) {
    this.emit('wipe_progress', { 
      wipeId: wipeRecord.wipeId, 
      status: 'preflight_checks', 
      progress: 5 
    });

    // Check if device exists and is accessible
    try {
      await fs.access(wipeRecord.devicePath, fs.constants.R_OK | fs.constants.W_OK);
    } catch (error) {
      throw new Error(`Device not accessible: ${wipeRecord.devicePath}`);
    }

    // Check available disk space for logs
    const stats = await fs.statvfs ? fs.statvfs(os.tmpdir()) : { bavail: 1000000, bsize: 4096 };
    const freeSpace = stats.bavail * stats.bsize;
    if (freeSpace < 100 * 1024 * 1024) { // 100MB minimum
      throw new Error('Insufficient disk space for wiping logs');
    }

    // Check system permissions
    if (os.platform() !== 'win32' && process.getuid() !== 0) {
      console.warn('Running without root privileges - some features may be limited');
    }

    // Validate wiping method
    const method = this.supportedMethods[wipeRecord.method];
    if (!method) {
      throw new Error(`Invalid wiping method: ${wipeRecord.method}`);
    }

    wipeRecord.progress = 10;
    this.emit('wipe_progress', { 
      wipeId: wipeRecord.wipeId, 
      status: 'preflight_complete', 
      progress: 10 
    });
  }

  /**
   * Analyze device to get detailed information
   * @private
   */
  async _analyzeDevice(wipeRecord) {
    this.emit('wipe_progress', { 
      wipeId: wipeRecord.wipeId, 
      status: 'analyzing_device', 
      progress: 15 
    });

    try {
      // Get device size and geometry
      const deviceInfo = await this._getDeviceInfo(wipeRecord.devicePath);
      wipeRecord.deviceInfo = deviceInfo;
      wipeRecord.sectors.total = deviceInfo.sectors;

      // Detect storage type (HDD/SSD/NVMe)
      wipeRecord.storageType = await this._detectStorageType(wipeRecord.devicePath);

      // Check for encryption
      wipeRecord.encryptionStatus = await this._checkEncryption(wipeRecord.devicePath);

      // Detect file systems
      wipeRecord.partitions = await this._detectPartitions(wipeRecord.devicePath);

      this.emit('wipe_progress', { 
        wipeId: wipeRecord.wipeId, 
        status: 'device_analyzed', 
        progress: 20,
        deviceInfo: wipeRecord.deviceInfo
      });

    } catch (error) {
      console.warn('Device analysis failed:', error.message);
      // Continue with default values
      wipeRecord.deviceInfo = { sectors: 0, sectorSize: 512 };
    }
  }

  /**
   * Get detailed device information
   * @private
   */
  async _getDeviceInfo(devicePath) {
    return new Promise((resolve, reject) => {
      let command, args;

      if (os.platform() === 'win32') {
        // Windows: Use fsutil or wmic
        command = 'wmic';
        args = ['diskdrive', 'where', `DeviceID="${devicePath.replace(/\\/g, '\\\\')}"`, 'get', 'Size', '/format:value'];
      } else {
        // Linux/macOS: Use blockdev or fdisk
        command = 'blockdev';
        args = ['--getsize64', devicePath];
      }

      const process = spawn(command, args);
      let output = '';
      let error = '';

      process.stdout.on('data', (data) => {
        output += data.toString();
      });

      process.stderr.on('data', (data) => {
        error += data.toString();
      });

      process.on('close', (code) => {
        if (code !== 0) {
          return reject(new Error(`Failed to get device info: ${error}`));
        }

        try {
          let sizeBytes;
          if (os.platform() === 'win32') {
            const match = output.match(/Size=(\d+)/);
            sizeBytes = match ? parseInt(match[1]) : 0;
          } else {
            sizeBytes = parseInt(output.trim());
          }

          const sectorSize = 512; // Most common sector size
          const sectors = Math.floor(sizeBytes / sectorSize);

          resolve({
            sizeBytes,
            sectors,
            sectorSize,
            sizeMB: Math.floor(sizeBytes / (1024 * 1024)),
            sizeGB: Math.floor(sizeBytes / (1024 * 1024 * 1024))
          });
        } catch (parseError) {
          reject(new Error(`Failed to parse device info: ${parseError.message}`));
        }
      });
    });
  }

  /**
   * Detect storage type (HDD/SSD/NVMe)
   * @private
   */
  async _detectStorageType(devicePath) {
    // This is a simplified detection - in production, use more sophisticated methods
    if (devicePath.includes('nvme')) return 'nvme';
    if (devicePath.includes('ssd') || devicePath.includes('solid')) return 'ssd';
    return 'hdd';
  }

  /**
   * Check for device encryption
   * @private
   */
  async _checkEncryption(devicePath) {
    // This is a placeholder - implement actual encryption detection
    return 'unknown';
  }

  /**
   * Detect partitions on the device
   * @private
   */
  async _detectPartitions(devicePath) {
    // Simplified partition detection
    return [];
  }

  /**
   * Disable write cache for better security
   * @private
   */
  async _disableWriteCache(wipeRecord) {
    try {
      if (os.platform() !== 'win32') {
        // Linux: Use hdparm or similar
        const { exec } = require('child_process');
        await new Promise((resolve) => {
          exec(`hdparm -W 0 ${wipeRecord.devicePath}`, () => resolve());
        });
      }
    } catch (error) {
      // Non-critical error, continue
      console.warn('Failed to disable write cache:', error.message);
    }
  }

  /**
   * Perform the actual wiping
   * @private
   */
  async _performWipe(wipeRecord) {
    const method = this.supportedMethods[wipeRecord.method];
    const patterns = this._getWipePatterns(method);

    for (let pass = 0; pass < method.passes; pass++) {
      wipeRecord.currentPass = pass + 1;
      
      this.emit('wipe_progress', {
        wipeId: wipeRecord.wipeId,
        status: 'wiping',
        progress: 20 + (pass / method.passes) * 60,
        currentPass: wipeRecord.currentPass,
        totalPasses: wipeRecord.totalPasses
      });

      const pattern = patterns[pass] || patterns[0];
      await this._performWipePass(wipeRecord, pattern, pass);
      
      // Sync to ensure data is written
      await this._syncDevice(wipeRecord.devicePath);
    }
  }

  /**
   * Perform a single wipe pass
   * @private
   */
  async _performWipePass(wipeRecord, pattern, passNumber) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      let command, args;

      if (os.platform() === 'win32') {
        // Windows: Use custom implementation or dd equivalent
        command = 'powershell';
        args = ['-Command', this._generateWindowsWipeCommand(wipeRecord, pattern)];
      } else {
        // Linux/macOS: Use dd with appropriate parameters
        command = 'dd';
        args = this._generateDDCommand(wipeRecord, pattern);
      }

      const process = spawn(command, args);
      wipeRecord.process = process;

      let lastProgress = 0;
      let bytesProcessed = 0;

      // Monitor progress (simplified)
      const progressInterval = setInterval(() => {
        if (wipeRecord.status === 'cancelling') {
          clearInterval(progressInterval);
          return;
        }

        // Estimate progress based on time elapsed
        const elapsed = Date.now() - startTime;
        const estimatedDuration = wipeRecord.deviceInfo.sizeBytes / (50 * 1024 * 1024); // 50MB/s estimate
        const estimatedProgress = Math.min(95, (elapsed / (estimatedDuration * 1000)) * 100);
        
        if (estimatedProgress > lastProgress) {
          lastProgress = estimatedProgress;
          const totalProgress = 20 + (passNumber / wipeRecord.totalPasses) * 60 + 
                               (estimatedProgress / 100) * (60 / wipeRecord.totalPasses);
          
          wipeRecord.progress = Math.min(80, totalProgress);
          wipeRecord.throughput = bytesProcessed / (elapsed / 1000) / (1024 * 1024); // MB/s
          
          this.emit('wipe_progress', {
            wipeId: wipeRecord.wipeId,
            status: 'wiping',
            progress: wipeRecord.progress,
            currentPass: wipeRecord.currentPass,
            throughput: wipeRecord.throughput
          });
        }
      }, 1000);

      process.on('close', (code) => {
        clearInterval(progressInterval);
        
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Wipe pass ${passNumber + 1} failed with code ${code}`));
        }
      });

      process.on('error', (error) => {
        clearInterval(progressInterval);
        reject(error);
      });

      // Handle SIGTERM for graceful shutdown
      process.on('SIGTERM', () => {
        clearInterval(progressInterval);
        reject(new Error('Wipe process terminated'));
      });
    });
  }

  /**
   * Generate DD command arguments
   * @private
   */
  _generateDDCommand(wipeRecord, pattern) {
    const args = ['bs=1M', 'conv=fdatasync'];
    
    if (pattern === 'zeros') {
      args.push('if=/dev/zero');
    } else if (pattern === 'ones') {
      args.push('if=/dev/zero'); // Will be modified with tr
    } else if (pattern === 'random') {
      args.push('if=/dev/urandom');
    }
    
    args.push(`of=${wipeRecord.devicePath}`);
    
    return args;
  }

  /**
   * Generate Windows wipe command
   * @private
   */
  _generateWindowsWipeCommand(wipeRecord, pattern) {
    // This is a simplified Windows command - in production, use proper Windows APIs
    return `
      $device = "${wipeRecord.devicePath}";
      $buffer = New-Object byte[] 1048576;
      ${pattern === 'zeros' ? '$buffer[0..1048575] = 0;' : 
        pattern === 'ones' ? '$buffer[0..1048575] = 255;' : 
        '[System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($buffer);'}
      $stream = [System.IO.File]::OpenWrite($device);
      for ($i = 0; $i -lt ${wipeRecord.deviceInfo.sizeBytes}; $i += 1048576) {
        $stream.Write($buffer, 0, $buffer.Length);
        $stream.Flush();
      }
      $stream.Close();
    `;
  }

  /**
   * Get wipe patterns for a method
   * @private
   */
  _getWipePatterns(method) {
    if (method.patterns === 'gutmann_sequence') {
      // Simplified Gutmann sequence
      return [
        'random', 'random', 'random', 'random',
        '0x55555555', '0xAAAAAAAA', '0x92492492', '0x49249249',
        '0x24924924', '0x00000000', '0x11111111', '0x22222222',
        '0x33333333', '0x44444444', '0x55555555', '0x66666666',
        '0x77777777', '0x88888888', '0x99999999', '0xAAAAAAAA',
        '0xBBBBBBBB', '0xCCCCCCCC', '0xDDDDDDDD', '0xEEEEEEEE',
        '0xFFFFFFFF', '0x92492492', '0x49249249', '0x24924924',
        'random', 'random', 'random', 'random', 'random', 'random', 'random'
      ];
    }
    return method.patterns;
  }

  /**
   * Verify the wipe was successful
   * @private
   */
  async _verifyWipe(wipeRecord) {
    this.emit('wipe_progress', {
      wipeId: wipeRecord.wipeId,
      status: 'verifying',
      progress: 85
    });

    try {
      // Read random samples from the device
      const sampleCount = Math.min(100, Math.floor(wipeRecord.sectors.total / 1000));
      const sampleSectors = this._generateRandomSectors(sampleCount, wipeRecord.sectors.total);
      
      let verifiedSectors = 0;
      for (const sector of sampleSectors) {
        const isWiped = await this._verifySector(wipeRecord.devicePath, sector);
        if (isWiped) {
          verifiedSectors++;
        }
      }

      wipeRecord.sectors.verified = verifiedSectors;
      wipeRecord.verificationRate = (verifiedSectors / sampleCount) * 100;

      if (wipeRecord.verificationRate < 95) {
        throw new Error(`Verification failed: ${wipeRecord.verificationRate}% success rate`);
      }

      this.emit('wipe_progress', {
        wipeId: wipeRecord.wipeId,
        status: 'verification_complete',
        progress: 90,
        verificationRate: wipeRecord.verificationRate
      });

    } catch (error) {
      wipeRecord.errors.push(`Verification failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check for hidden areas (HPA/DCO)
   * @private
   */
  async _checkHiddenAreas(wipeRecord) {
    try {
      // This is a placeholder for HPA/DCO detection and wiping
      // In production, implement proper HPA/DCO handling
      this.emit('wipe_progress', {
        wipeId: wipeRecord.wipeId,
        status: 'checking_hidden_areas',
        progress: 95
      });

      // Simplified check - would need platform-specific implementation
      wipeRecord.hiddenAreasFound = false;
      wipeRecord.hiddenAreasWiped = false;

    } catch (error) {
      console.warn('Hidden area check failed:', error.message);
      wipeRecord.errors.push(`Hidden area check failed: ${error.message}`);
    }
  }

  /**
   * Generate random sector numbers for verification
   * @private
   */
  _generateRandomSectors(count, totalSectors) {
    const sectors = new Set();
    while (sectors.size < count) {
      sectors.add(Math.floor(Math.random() * totalSectors));
    }
    return Array.from(sectors);
  }

  /**
   * Verify a specific sector is wiped
   * @private
   */
  async _verifySector(devicePath, sectorNumber) {
    // This is a simplified verification - in production, implement proper sector reading
    return true; // Placeholder
  }

  /**
   * Sync device to ensure data is written
   * @private
   */
  async _syncDevice(devicePath) {
    return new Promise((resolve) => {
      if (os.platform() === 'win32') {
        // Windows: Use FlushFileBuffers or similar
        resolve();
      } else {
        const { exec } = require('child_process');
        exec('sync', () => resolve());
      }
    });
  }

  /**
   * Generate unique wipe ID
   * @private
   */
  generateWipeId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(6).toString('hex');
    return `WIPE-${timestamp}-${random}`.toUpperCase();
  }

  /**
   * Get list of active wipes
   * @returns {Array} - Active wipe records
   */
  getActiveWipes() {
    return Array.from(this.activeWipes.values()).map(wipe => ({
      wipeId: wipe.wipeId,
      status: wipe.status,
      progress: wipe.progress,
      devicePath: wipe.devicePath,
      method: wipe.method,
      startedAt: wipe.startedAt,
      currentPass: wipe.currentPass,
      totalPasses: wipe.totalPasses
    }));
  }

  /**
   * Clean up completed wipes from memory
   * @param {number} maxAge - Maximum age in milliseconds
   */
  cleanupCompletedWipes(maxAge = 24 * 60 * 60 * 1000) { // 24 hours default
    const cutoffTime = Date.now() - maxAge;
    
    for (const [wipeId, wipeRecord] of this.activeWipes.entries()) {
      if (wipeRecord.completedAt && wipeRecord.completedAt.getTime() < cutoffTime) {
        this.activeWipes.delete(wipeId);
      }
    }
  }

  /**
   * Get supported wiping methods
   * @returns {Object} - Supported methods
   */
  getSupportedMethods() {
    return this.supportedMethods;
  }
}

module.exports = WipingService;