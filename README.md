# Secure Data Wiper - Trustworthy IT Asset Recycling

## Problem Statement
India faces a growing e-waste crisis with over 1.75 million tonnes generated annually. This application addresses the fear of data breaches that prevents proper IT asset recycling by providing secure, verifiable data wiping.

## Solution Overview
A secure, cross-platform data wiping application that:
- Securely erases all user data including hidden storage areas (HPA/DCO, SSD sectors)
- Generates digitally signed, tamper-proof wipe certificates (PDF & JSON)
- Features intuitive one-click interface for general public use
- Works offline via bootable ISO/USB
- Enables third-party verification of wipe status
- Complies with NIST SP 800-88 standards

## Tech Stack
- **Backend**: Node.js, Express.js, MongoDB
- **Frontend**: React.js
- **Mobile**: React Native (Android)
- **Security**: OpenSSL, crypto libraries
- **Certificates**: PDFKit, digital signatures

## Project Structure
```
secure-data-wiper/
├── backend/           # Express.js API server
├── frontend/          # React.js web application
├── mobile/            # React Native Android app
├── bootable-utils/    # Offline bootable tools
├── shared/            # Common utilities and libraries
├── certificates/      # Certificate templates and samples
└── docs/             # Documentation and specifications
```

## Key Features
1. **Multi-Platform Support**: Windows, Linux, Android
2. **NIST SP 800-88 Compliance**: Industry-standard data sanitization
3. **Tamper-Proof Certificates**: Cryptographically signed verification
4. **Offline Capability**: Bootable ISO for air-gapped wiping
5. **Third-Party Verification**: External validation system
6. **User-Friendly Interface**: One-click operation for general public

## Impact Goals
- Build user confidence in device recycling
- Reduce IT asset hoarding (₹50,000+ crore value)
- Promote safe e-waste management
- Advance India's circular economy initiatives

## Getting Started
See individual module READMEs for setup instructions:
- [Backend Setup](./backend/README.md)
- [Frontend Setup](./frontend/README.md)
- [Mobile Setup](./mobile/README.md)

## License
MIT License - Supporting India's e-waste management initiatives

## Contributing
This project supports the Ministry of Mines and JNARDDC initiative for sustainable IT asset recycling.