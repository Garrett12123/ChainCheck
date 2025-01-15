# Chain Check

A comprehensive Python tool for SSL/TLS certificate chain inspection, validation, and security analysis.

## Features

### Certificate Chain Analysis
- Fetch and validate complete certificate chains
- Display certificate hierarchy (leaf, intermediate, root)
- Extract Subject Alternative Names (SAN)
- Export certificates to PEM files
- Save detailed chain information in JSON format

### Security Testing
- Test supported TLS versions (1.2, 1.3)
- Analyze cipher suites
- Check for common vulnerabilities
- Verify secure renegotiation support
- Monitor certificate expiration

### Server Health Checks
- Measure response times
- Verify HTTP security headers
- Test TCP connection health
- Analyze SSL/TLS configuration

### Advanced Features
- Certificate Transparency (CT) log analysis
- Historical certificate tracking
- Multiple CA detection
- Comprehensive security scanning
- Detailed security recommendations

### User Interface
- Interactive CLI with domain autocompletion
- Color-coded output for better readability
- Detailed progress information
- Comprehensive error messages
- Clean, organized menu system

## Installation

1. First, make sure you have Python installed:
   - For Windows: Download from [python.org](https://www.python.org/downloads/)
   - For Mac: `brew install python3`
   - For Linux: `sudo apt install python3 python3-pip` (Ubuntu/Debian) or `sudo dnf install python3 python3-pip` (Fedora)

2. Clone the repository:
```bash
git clone https://github.com/Garrett12123/ChainCheck.git
cd ChainCheck
```

3. Install required dependencies:
```bash
python3 -m pip install -r requirements.txt
```

## Usage

### Basic Command Line Mode
```bash
python3 ChainCheck.py example.com
```

### Interactive Mode
```bash
python3 ChainCheck.py -i
```

### Available Commands in Interactive Mode
1. **Fetch SSL Chain** - Get complete certificate chain and validation status
2. **Save PEM Files** - Export certificates to individual PEM files
3. **Export JSON Details** - Save certificate details in structured JSON format
4. **Protocol Check** - Test supported TLS versions and cipher suites
5. **Vulnerability Scan** - Check for common SSL/TLS vulnerabilities
6. **Server Health** - Test response times and security headers
7. **Certificate Logs** - Search CT logs for historical certificates
8. **Full Security Scan** - Comprehensive analysis of all security aspects

## Common Issues

1. If you get "command not found: pip":
   - Make sure Python is installed
   - Try using `python -m pip` or `python3 -m pip` instead

2. If you get SSL/TLS errors:
   - Make sure your system's SSL certificates are up to date
   - Try updating certifi: `python3 -m pip install --upgrade certifi`
   - On Linux systems, you might need to install ca-certificates:
     ```bash
     # Ubuntu/Debian
     sudo apt-get install ca-certificates
     
     # Fedora
     sudo dnf install ca-certificates
     ```

3. If you get certificate verification errors:
   - The script will attempt to use certifi's certificate bundle
   - You can manually specify a certificate bundle path:
     ```bash
     export SSL_CERT_FILE=/path/to/cacert.pem
     ```

## Requirements

- Python 3.6 or higher
- OpenSSL
- Network access to target domains
- Required Python packages (see requirements.txt)

## Security Note

This tool is for diagnostic purposes only. Always follow security best practices and keep your systems updated with the latest security patches.

## Contributing

Contributions are welcome! Please feel free to:
- Submit pull requests
- Report bugs
- Suggest new features
- Improve documentation

## License

MIT License - See [LICENSE](LICENSE) for details.
