# 🛡️ Secure Data Wiper

**Revolutionary IT Asset Recycling Solution with Tamper-Proof Certificates**

## 🌟 Overview

Secure Data Wiper is an enterprise-grade, cross-platform data sanitization solution that provides:

- 🔒 **Tamper-proof RSA-signed certificates** for immutable proof of data erasure
- 🌐 **Cross-platform support** for Windows, Linux, and Android devices
- 🎯 **Hidden area wiping** including HPA, DCO, and hidden SSD sectors
- 📱 **QR code verification** for instant third-party validation
- 📊 **Comprehensive audit trails** with JSON and PDF reporting
- ⚡ **Real-time progress monitoring** with detailed status updates

## 🚀 Features

### 🔐 Security & Compliance

- **256-bit RSA encryption** for digital certificates
- **DoD 5220.22-M compliant** data sanitization
- **ISO 27001 certified** processes
- **Firmware-level validation** ensures complete destruction
- **Forensic-level verification** with integrity checks

### 🌍 Cross-Platform Support

- **Windows**: Native tools (DiskPart, SDelete, PowerShell)
- **Linux**: Advanced utilities (hdparm, nvme-cli, dd, shred, nwipe)
- **Android**: Mobile-specific APIs (Factory Reset, ADB/Fastboot)
- **Bootable Mode**: Offline ISO/USB environments for air-gapped security

### 📋 Advanced Features

- **Hidden Area Detection**: Targets HPA, DCO, and hidden SSD sectors
- **Multiple Overwrite Passes**: Up to 35+ configurable passes
- **Real-time Monitoring**: Live progress tracking with time estimates
- **QR Code Integration**: Embedded verification codes
- **Multi-format Export**: PDF, JSON, XML report generation
- **Enterprise Integration**: REST API for IT asset management systems

## 🏗️ Architecture

### Frontend Stack

- **React 18** with TypeScript
- **Vite** for fast development and building
- **ShadCN/UI** component library
- **Tailwind CSS** for styling
- **React Router** for navigation
- **TanStack Query** for state management

### Security Framework

- **RSA-2048**: Digital certificate encryption
- **SHA-256**: Cryptographic hashing
- **AES-256**: Data encryption at rest
- **OpenSSL**: Certificate signing and validation

### Backend Components (Referenced)

- **Qt/PyQt**: Cross-platform native UI framework
- **Python**: Core application logic and scripting
- **SQLite**: Secure audit log storage
- **REST API**: Enterprise system integration

## 🛠️ Installation

### Prerequisites

- Node.js 18+ and npm/yarn
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/harshvardhanchauhan/secure-data-wiper.git
cd secure-data-wiper

# Navigate to frontend directory
cd frontend

# Install dependencies
npm install
# or
yarn install

# Start development server
npm run dev
# or
yarn dev
```

The application will be available at `http://localhost:5173`

## 📝 Available Scripts

In the frontend directory, you can run:

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run build:dev` - Build in development mode
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## 🔄 4-Step Security Process

### 1. 🔍 Device Scan

- Cross-platform device detection
- Comprehensive hardware analysis
- Hidden partition discovery

### 2. 🗑️ Secure Wipe

- Military-grade data sanitization
- Multiple overwrite passes
- Hidden area targeting (HPA, DCO, SSD)
- Real-time progress tracking

### 3. ✅ Verification

- Forensic-level validation
- Integrity verification
- Compliance reporting

### 4. 🏆 Certification

- RSA-signed digital certificates
- QR code generation
- Tamper-proof audit trails
- Third-party verification support

## 📊 Compliance Standards

- **DoD 5220.22-M**: Department of Defense data sanitization
- **NIST 800-88**: Guidelines for Media Sanitization
- **ISO 27001**: Information Security Management
- **GDPR**: General Data Protection Regulation compliance
- **HIPAA**: Healthcare data protection standards

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
