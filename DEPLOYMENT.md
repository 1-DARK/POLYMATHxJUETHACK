# JNARDDC Secure Data Wiper - Deployment Guide

## Ministry of Mines, Government of India
### Jawaharlal Nehru Aluminium Research Development and Design Centre (JNARDDC)

---

## 🚀 Quick Start

This guide provides step-by-step instructions to deploy the JNARDDC Secure Data Wiper application across different environments.

## 📋 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+ / CentOS 8+ / Windows Server 2019+
- **Memory**: 4 GB RAM
- **Storage**: 50 GB free space
- **CPU**: 2 cores, 2.4 GHz+
- **Network**: 1 Gbps connection

### Recommended Requirements
- **OS**: Ubuntu 22.04 LTS
- **Memory**: 8 GB RAM
- **Storage**: 100 GB SSD
- **CPU**: 4 cores, 3.0 GHz+
- **Network**: 10 Gbps connection

## 🔧 Prerequisites

### 1. Install Node.js and npm
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# CentOS/RHEL
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs

# Verify installation
node --version  # Should be v18.x or higher
npm --version   # Should be 9.x or higher
```

### 2. Install MongoDB
```bash
# Ubuntu
sudo apt-get install gnupg curl
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo \"deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse\" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
```

### 3. Install Git
```bash
# Ubuntu/Debian
sudo apt-get install git

# CentOS/RHEL
sudo yum install git
```

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/jnarddc/secure-data-wiper.git
cd secure-data-wiper
```

### 2. Backend Setup
```bash
cd backend

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit environment variables
nano .env
```

#### Environment Configuration (.env)
```env
# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/secure-data-wiper

# Server Configuration
PORT=3001
NODE_ENV=production

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-256-bits
JWT_EXPIRE=7d

# Certificate Signing Keys
CERTIFICATE_PRIVATE_KEY_PATH=./certificates/private.key
CERTIFICATE_PUBLIC_KEY_PATH=./certificates/public.key

# API Security
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Government Authority Details
CERTIFICATE_AUTHORITY_NAME=\"JNARDDC Secure Wipe Authority\"
VERIFICATION_BASE_URL=https://verify.jnarddc.gov.in
```

### 3. Generate SSL Certificates
```bash
# Create certificates directory
mkdir -p certificates

# Generate RSA key pair for certificate signing
openssl genrsa -out certificates/private.key 4096
openssl rsa -in certificates/private.key -pubout -out certificates/public.key

# Generate SSL certificates for HTTPS
openssl req -x509 -newkey rsa:4096 -keyout certificates/ssl-private.key -out certificates/ssl-cert.pem -days 365 -nodes
```

### 4. Initialize Database
```bash
# Create database indexes and initial data
npm run db:init

# Create admin user (optional)
npm run db:create-admin
```

### 5. Start Backend Server
```bash
# Development mode
npm run dev

# Production mode
npm start
```

### 6. Frontend Setup
```bash
cd ../frontend

# Install dependencies
npm install

# Build for production
npm run build

# Serve static files (using nginx or serve)
npm install -g serve
serve -s build -p 3000
```

### 7. Mobile App Setup (Android)
```bash
cd ../mobile

# Install dependencies
npm install

# For Android development
# Ensure Android Studio and SDK are installed
npx react-native run-android --variant=release
```

## 🐳 Docker Deployment

### 1. Using Docker Compose
```bash
# Create docker-compose.yml in project root
version: '3.8'
services:
  mongodb:
    image: mongo:7.0
    container_name: jnarddc-mongo
    restart: always
    ports:
      - \"27017:27017\"
    volumes:
      - mongodb_data:/data/db
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: secure_password
      MONGO_INITDB_DATABASE: secure-data-wiper

  backend:
    build: ./backend
    container_name: jnarddc-backend
    restart: always
    ports:
      - \"3001:3001\"
    depends_on:
      - mongodb
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://admin:secure_password@mongodb:27017/secure-data-wiper?authSource=admin
      - JWT_SECRET=your-production-jwt-secret
    volumes:
      - ./backend/certificates:/app/certificates
      - ./backend/logs:/app/logs

  frontend:
    build: ./frontend
    container_name: jnarddc-frontend
    restart: always
    ports:
      - \"3000:80\"
    depends_on:
      - backend

volumes:
  mongodb_data:
```

### 2. Deploy with Docker Compose
```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## ⚖️ Production Configuration

### 1. Nginx Configuration
```nginx
# /etc/nginx/sites-available/secure-data-wiper
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/ssl-cert.pem;
    ssl_certificate_key /path/to/ssl-private.key;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";
}
```

### 2. PM2 Process Management
```bash
# Install PM2
npm install -g pm2

# Create ecosystem file
# ecosystem.config.js
module.exports = {
  apps: [{
    name: 'jnarddc-backend',
    script: './backend/server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3001
    },
    error_file: './logs/backend-error.log',
    out_file: './logs/backend-out.log',
    log_file: './logs/backend-combined.log',
    max_memory_restart: '1G'
  }]
};

# Start with PM2
pm2 start ecosystem.config.js

# Save PM2 configuration
pm2 save
pm2 startup
```

## 🎯 Bootable ISO Creation

### 1. Linux Environment Setup
```bash
# Install required tools (Ubuntu)
sudo apt-get update
sudo apt-get install debootstrap squashfs-tools xorriso isolinux syslinux-utils

# Make the script executable
chmod +x bootable-utils/create-bootable-wiper.sh

# Run the ISO creation script
sudo ./bootable-utils/create-bootable-wiper.sh
```

### 2. ISO Usage
```bash
# The script will generate:
# - JNARDDC-Secure-Wiper-v1.0.iso (bootable image)
# - JNARDDC-Secure-Wiper-v1.0.iso.sha256 (checksum)
# - JNARDDC-Secure-Wiper-v1.0.iso.md5 (checksum)

# Verify integrity
sha256sum -c JNARDDC-Secure-Wiper-v1.0.iso.sha256

# Create bootable USB
sudo dd if=JNARDDC-Secure-Wiper-v1.0.iso of=/dev/sdX bs=4M status=progress
sudo sync
```

## 🔒 Security Configuration

### 1. SSL/TLS Setup
```bash
# Generate production SSL certificates
# Using Let's Encrypt
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com

# Or use your organization's CA certificates
# Place certificates in /etc/ssl/certs/
sudo cp your-cert.pem /etc/ssl/certs/
sudo cp your-private-key.pem /etc/ssl/private/
sudo chmod 600 /etc/ssl/private/your-private-key.pem
```

### 2. Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable

# iptables (CentOS/RHEL)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 3. MongoDB Security
```bash
# Create application user
mongo
use secure-data-wiper
db.createUser({
  user: \"app_user\",
  pwd: \"secure_password\",
  roles: [
    { role: \"readWrite\", db: \"secure-data-wiper\" }
  ]
})

# Enable authentication in /etc/mongod.conf
security:
  authorization: enabled
```

## 📊 Monitoring and Logging

### 1. Application Monitoring
```bash
# Install monitoring tools
npm install -g @datadog/datadog-ci  # If using Datadog
# Or setup Prometheus + Grafana

# Enable application metrics
# Add to backend/server.js
const prometheus = require('prom-client');
const collectDefaultMetrics = prometheus.collectDefaultMetrics;
collectDefaultMetrics();
```

### 2. Log Management
```bash
# Configure log rotation
# /etc/logrotate.d/secure-data-wiper
/path/to/secure-data-wiper/logs/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    create 644 app app
}
```

## 🧪 Testing and Validation

### 1. Run Security Audit
```bash
cd backend
node tests/wiping-security-audit.js
```

### 2. API Testing
```bash
# Install testing tools
npm install -g newman

# Run API tests
newman run tests/api-tests.postman_collection.json
```

### 3. Load Testing
```bash
# Install artillery
npm install -g artillery

# Run load tests
artillery run tests/load-test.yml
```

## 🔄 Backup and Recovery

### 1. Database Backup
```bash
#!/bin/bash
# backup-script.sh
BACKUP_DIR=\"/var/backups/jnarddc\"
DATE=$(date +\"%Y%m%d_%H%M%S\")
BACKUP_FILE=\"$BACKUP_DIR/mongodb_backup_$DATE\"

# Create backup
mongodump --uri=\"mongodb://admin:password@localhost:27017/secure-data-wiper?authSource=admin\" --out=\"$BACKUP_FILE\"

# Compress backup
tar -czf \"$BACKUP_FILE.tar.gz\" -C \"$BACKUP_DIR\" \"mongodb_backup_$DATE\"
rm -rf \"$BACKUP_FILE\"

# Remove old backups (keep 30 days)
find \"$BACKUP_DIR\" -name \"mongodb_backup_*.tar.gz\" -mtime +30 -delete
```

### 2. Application Backup
```bash
# Backup certificates and configuration
tar -czf \"app_backup_$(date +%Y%m%d).tar.gz\" \
    backend/certificates/ \
    backend/.env \
    frontend/build/ \
    nginx/sites-available/
```

## 🚨 Troubleshooting

### Common Issues

#### 1. MongoDB Connection Issues
```bash
# Check MongoDB status
sudo systemctl status mongod

# Check connection
mongo --eval \"db.adminCommand('ismaster')\"

# Check logs
sudo tail -f /var/log/mongodb/mongod.log
```

#### 2. Permission Issues
```bash
# Fix file permissions
sudo chown -R app:app /path/to/secure-data-wiper
sudo chmod -R 755 /path/to/secure-data-wiper
sudo chmod 600 backend/certificates/private.key
```

#### 3. SSL Certificate Issues
```bash
# Test SSL certificate
openssl x509 -in /path/to/cert.pem -text -noout
openssl s_client -connect your-domain.com:443
```

#### 4. High Memory Usage
```bash
# Monitor memory usage
htop
free -h

# Restart services if needed
pm2 restart all
sudo systemctl restart nginx
```

## 📞 Support

### Government Support Channels
- **Technical Support**: tech-support@jnarddc.gov.in
- **Security Issues**: security@jnarddc.gov.in
- **General Inquiries**: info@jnarddc.gov.in

### Documentation
- **API Documentation**: https://api.jnarddc.gov.in/docs
- **User Manual**: https://docs.jnarddc.gov.in/secure-wiper
- **Security Guidelines**: https://security.jnarddc.gov.in/guidelines

## 📜 Compliance

This application has been developed in compliance with:
- **NIST SP 800-88 Rev. 1** - Guidelines for Media Sanitization
- **ISO/IEC 27001** - Information Security Management
- **Government of India IT Security Guidelines**
- **Data Protection Act 2023**

## 📄 License

Copyright (c) 2024 Ministry of Mines, Government of India  
Licensed under the terms specified in the project license.

---

**Note**: This deployment guide is for authorized government personnel only. Ensure all security protocols are followed during deployment and operation.