# Chain Check

A lightweight Python tool for SSL/TLS certificate chain inspection and validation.

## Features

- **SSL Chain Inspection**: Fetch and display detailed certificate information
- **Expiration Monitoring**: Get alerts for certificates nearing expiration
- **Chain Validation**: Verify certificate chain integrity and trust relationships
- **Interactive CLI**: User-friendly interface with domain autocompletion

## Installation

1. Install required dependencies:
```bash
pip install OpenSSL asn1crypto certvalidator prompt_toolkit tabulate tqdm
```

2. Download the script:
```bash
wget https://raw.githubusercontent.com/chaincheck/chaincheck/main/chaincheck.py
```

## Usage

### Command Line Mode
```bash
python chaincheck.py example.com
```

### Interactive Mode
```bash
python chaincheck.py -i
```

## Output Example
```
Certificate Chain Details for example.com:

Leaf Certificate
  Subject: CN=example.com
  Issuer: CN=Let's Encrypt Authority X3
  Valid From: 2024-01-01
  Valid To: 2024-03-31
  Signature Algorithm: sha256WithRSAEncryption
  Subject Alternative Names (SAN): example.com, www.example.com

Chain Validation Results:
- Certificate chain is valid
- Certificate 0 valid until 2024-03-31 (60 days left)
```

## Requirements

- Python 3.6+
- OpenSSL
- Network access to target domains

## Features in Detail

- **Certificate Analysis**: Detailed inspection of SSL/TLS certificates
- **Chain Validation**: Verification of certificate chain integrity
- **Expiration Checks**: Monitoring of certificate expiration dates
- **Interactive Mode**: User-friendly command-line interface
- **SAN Validation**: Subject Alternative Name verification
- **Colored Output**: Clear, readable terminal output

## License

MIT License - See [LICENSE](LICENSE) for details.

## Author

Garrett Flowers  

## Contributing

Contributions are welcome. Please submit pull requests or open issues for any improvements.
