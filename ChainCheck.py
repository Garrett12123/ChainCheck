# SSL Chain Checker with Interactive CLI and Enhancements

# -----------------------------------
# 1. Import Libraries
# -----------------------------------
import os
import sys
import socket
import logging
from datetime import datetime, timezone
import argparse
import traceback
from concurrent.futures import ThreadPoolExecutor
from OpenSSL import SSL, crypto
from asn1crypto import x509 as asn1_x509
from certvalidator import CertificateValidator, ValidationContext, errors as validator_errors
from tabulate import tabulate
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from tqdm import tqdm
import ssl  # Added import
import json
from pathlib import Path
import certifi
import requests
import warnings

# -----------------------------------
# 2. Constants and Configuration
# -----------------------------------
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

LOG_FILE = "ssl_chain_checker.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info("SSL Chain Checker Initialized.")

# -----------------------------------
# 3. Helper Functions
# -----------------------------------

def get_certificate_chain(hostname, port=443, timeout=5):
    """Retrieve the SSL certificate chain from the given domain."""
    try:
        context = SSL.Context(SSL.TLS_METHOD)
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        context.set_verify(SSL.VERIFY_NONE, callback=lambda *args: True)

        sock = socket.create_connection((hostname, port), timeout=timeout)
        ssl_conn = SSL.Connection(context, sock)
        ssl_conn.set_tlsext_host_name(hostname.encode())
        ssl_conn.setblocking(True)
        ssl_conn.set_connect_state()
        ssl_conn.do_handshake()

        cert_chain = ssl_conn.get_peer_cert_chain()
        cert_chain_pem = [crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8') for cert in cert_chain]

        ssl_conn.close()
        sock.close()
        return cert_chain_pem
    except Exception as e:
        logging.error(f"Error retrieving certificate chain for {hostname}: {e}")
        print(f"{COLOR_RED}Error retrieving certificate chain for {hostname}:{COLOR_RESET} {e}")
        return None

def display_certificate_chain(cert_chain_pem, hostname):
    """Display SSL certificate chain details with color-coding."""
    print(f"\n{COLOR_BOLD}Certificate Chain Details for {hostname}:{COLOR_RESET}\n")

    for idx, cert_pem in enumerate(cert_chain_pem):
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        subject = cert.subject.human_friendly
        issuer = cert.issuer.human_friendly
        serial_number = hex(cert.serial_number)
        not_before = cert['tbs_certificate']['validity']['not_before'].native.strftime("%Y-%m-%d")
        not_after = cert['tbs_certificate']['validity']['not_after'].native.strftime("%Y-%m-%d")
        signature_algorithm = cert['tbs_certificate']['signature']['algorithm'].native

        if subject == issuer:
            cert_type = "Root"
            cert_type_color = COLOR_BLUE
        elif idx == 0:
            cert_type = "Leaf"
            cert_type_color = COLOR_GREEN
        else:
            cert_type = "Intermediate"
            cert_type_color = COLOR_YELLOW

        cert_type_display = f"{cert_type_color}{COLOR_BOLD}{cert_type} Certificate{COLOR_RESET}"

        print(f"{cert_type_display}")
        print(f"  {COLOR_BOLD}Subject:{COLOR_RESET} {subject}")
        print(f"  {COLOR_BOLD}Issuer:{COLOR_RESET} {issuer}")
        print(f"  {COLOR_BOLD}Serial Number:{COLOR_RESET} {serial_number}")
        print(f"  {COLOR_BOLD}Valid From:{COLOR_RESET} {not_before}")
        print(f"  {COLOR_BOLD}Valid To:{COLOR_RESET} {not_after}")
        print(f"  {COLOR_BOLD}Signature Algorithm:{COLOR_RESET} {signature_algorithm}")

        # Display SANs if present
        san_list = extract_san(cert_pem)
        if san_list:
            print(f"  {COLOR_BOLD}Subject Alternative Names (SAN):{COLOR_RESET} {', '.join(san_list)}\n")

def extract_san(cert_pem):
    """Extract Subject Alternative Names (SAN) from the certificate."""
    try:
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        extensions = cert['tbs_certificate']['extensions']
        san_extension = next(
            (ext['extn_value'].parsed for ext in extensions if ext['extn_id'].native == 'subject_alt_name'), None
        )
        return [name.native for name in san_extension if name.name == 'dns_name'] if san_extension else []
    except Exception as e:
        logging.error(f"Error extracting SAN: {e}")
        return []

def validate_certificate_chain(cert_chain_pem):
    """Validate the SSL certificate chain."""
    try:
        certificates = [asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem)) for cert_pem in cert_chain_pem]
        validator = CertificateValidator(certificates[0], certificates[1:], validation_context=ValidationContext())
        validator.validate_usage({'digital_signature', 'key_encipherment'})
        print(f"{COLOR_GREEN}{COLOR_BOLD}The certificate chain is valid.{COLOR_RESET}")
    except validator_errors.PathBuildingError:
        print(f"{COLOR_RED}Validation failed: Missing intermediate certificates.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}Validation error: {e}{COLOR_RESET}")

def check_certificate_expiration(cert_chain_pem):
    """Check if any certificate in the chain is expired or about to expire."""
    warning_days = 30
    today = datetime.now(timezone.utc)
    for idx, cert_pem in enumerate(cert_chain_pem):
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        not_after = cert['tbs_certificate']['validity']['not_after'].native
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        days_to_expire = (not_after - today).days
        if days_to_expire < 0:
            print(f"{COLOR_RED}Certificate {idx} has expired on {not_after.strftime('%Y-%m-%d')}!{COLOR_RESET}")
        elif days_to_expire < warning_days:
            print(f"{COLOR_YELLOW}Certificate {idx} will expire in {days_to_expire} days on {not_after.strftime('%Y-%m-%d')}.{COLOR_RESET}")
        else:
            print(f"{COLOR_GREEN}Certificate {idx} is valid until {not_after.strftime('%Y-%m-%d')} ({days_to_expire} days left).{COLOR_RESET}")

def about_menu():
    """Display an about menu with usage information."""
    print(f"\n{COLOR_BOLD}About SSL Chain Checker{COLOR_RESET}")
    print("─" * 70)
    
    print(f"\n{COLOR_BLUE}Description:{COLOR_RESET}")
    print("A comprehensive tool for SSL/TLS certificate chain inspection, validation,")
    print("and security analysis. Designed for security professionals and system administrators.")
    
    print(f"\n{COLOR_BOLD}Core Features:{COLOR_RESET}")
    print(f"\n{COLOR_GREEN}1. Certificate Chain Analysis{COLOR_RESET}")
    print("   • Fetch and display complete certificate chains")
    print("   • View certificate hierarchy (leaf, intermediate, root)")
    print("   • Extract Subject Alternative Names (SAN)")
    print("   • Export certificates to PEM files")
    print("   • Save chain details in JSON format")
    
    print(f"\n{COLOR_GREEN}2. Security Validation{COLOR_RESET}")
    print("   • Verify certificate chain integrity")
    print("   • Monitor certificate expiration dates")
    print("   • Test TLS protocol support (1.2, 1.3)")
    print("   • Analyze cipher suites")
    print("   • Check for common vulnerabilities")
    print("   • Verify secure renegotiation support")
    
    print(f"\n{COLOR_GREEN}3. Interactive Features{COLOR_RESET}")
    print("   • User-friendly command-line interface")
    print("   • Domain name autocompletion")
    print("   • Color-coded output for better readability")
    print("   • Detailed security recommendations")
    print("   • Comprehensive error messages")
    
    print(f"\n{COLOR_BOLD}Usage Examples:{COLOR_RESET}")
    print(f"{COLOR_YELLOW}Basic Check:{COLOR_RESET}")
    print("  python3 ChainCheck.py example.com")
    print(f"\n{COLOR_YELLOW}Interactive Mode:{COLOR_RESET}")
    print("  python3 ChainCheck.py -i")
    
    print(f"\n{COLOR_BOLD}Security Note:{COLOR_RESET}")
    print("This tool is for diagnostic purposes only. Always follow security best")
    print("practices and keep your systems updated with the latest security patches.")
    
    print("\n" + "─" * 70 + "\n")

def save_certificates_to_files(cert_chain_pem, hostname):
    """Save certificates from the chain to individual PEM files."""
    output_dir = Path(f"certificates_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    output_dir.mkdir(exist_ok=True)
    
    saved_files = []
    for idx, cert_pem in enumerate(cert_chain_pem):
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        cert_type = "root" if cert.subject.human_friendly == cert.issuer.human_friendly else "intermediate" if idx > 0 else "leaf"
        filename = output_dir / f"{idx}_{cert_type}_{hostname}.pem"
        
        with open(filename, 'w') as f:
            f.write(cert_pem)
        saved_files.append(filename)
    
    print(f"{COLOR_GREEN}Certificates saved to directory: {output_dir}{COLOR_RESET}")
    return saved_files

def export_chain_details_json(cert_chain_pem, hostname):
    """Export certificate chain details to JSON format."""
    chain_details = []
    for cert_pem in cert_chain_pem:
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        cert_details = {
            'subject': cert.subject.human_friendly,
            'issuer': cert.issuer.human_friendly,
            'serial_number': hex(cert.serial_number),
            'not_before': cert['tbs_certificate']['validity']['not_before'].native.isoformat(),
            'not_after': cert['tbs_certificate']['validity']['not_after'].native.isoformat(),
            'signature_algorithm': cert['tbs_certificate']['signature']['algorithm'].native,
            'san': extract_san(cert_pem)
        }
        chain_details.append(cert_details)
    
    output_file = f"chain_details_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(chain_details, f, indent=2)
    print(f"{COLOR_GREEN}Chain details exported to: {output_file}{COLOR_RESET}")

def check_ssl_protocols(hostname, port=443):
    """Test supported SSL/TLS protocols."""
    print(f"\n{COLOR_BOLD}Testing SSL/TLS Protocol Support for {hostname}...{COLOR_RESET}")
    
    results = []
    
    # Suppress deprecation warnings
    with warnings.catch_warnings():
        warnings.filterwarnings('ignore', category=DeprecationWarning)
        
        # Test TLS 1.2
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for protocol check
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    if 'TLSv1.2' in version:
                        results.append(('TLSv1.2', True, cipher[0]))
                    else:
                        results.append(('TLSv1.2', False, None))
        except Exception as e:
            results.append(('TLSv1.2', False, None))
            logging.debug(f"TLS 1.2 test failed: {str(e)}")
        
        # Test TLS 1.3
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for protocol check
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    if 'TLSv1.3' in version:
                        results.append(('TLSv1.3', True, cipher[0]))
                    else:
                        results.append(('TLSv1.3', False, None))
        except Exception as e:
            results.append(('TLSv1.3', False, None))
            logging.debug(f"TLS 1.3 test failed: {str(e)}")
    
    # Print results in a clean table format
    print(f"\n{COLOR_BOLD}Protocol Support Summary:{COLOR_RESET}")
    print("─" * 70)
    print(f"{'Protocol':<12} │ {'Status':<20} │ {'Cipher Suite':<30}")
    print("─" * 70)
    
    for protocol, supported, cipher in results:
        if supported:
            status = f"{COLOR_GREEN}Supported{COLOR_RESET}"
            cipher_info = cipher
        else:
            status = f"{COLOR_RED}Not Supported{COLOR_RESET}"
            cipher_info = "N/A"
        
        print(f"{protocol:<12} │ {status:<40} │ {cipher_info if cipher_info else 'N/A'}")
    
    print("─" * 70)
    
    # Print security recommendations
    print(f"\n{COLOR_BOLD}Security Recommendations:{COLOR_RESET}")
    
    tls12_supported = any(r[0] == 'TLSv1.2' and r[1] for r in results)
    tls13_supported = any(r[0] == 'TLSv1.3' and r[1] for r in results)
    
    if tls12_supported:
        print(f"{COLOR_GREEN}✓ TLS 1.2 is supported (minimum recommended version){COLOR_RESET}")
    else:
        print(f"{COLOR_RED}✗ TLS 1.2 is not supported (minimum recommended version){COLOR_RESET}")
    
    if tls13_supported:
        print(f"{COLOR_GREEN}✓ TLS 1.3 is supported (best security){COLOR_RESET}")
    else:
        print(f"{COLOR_YELLOW}⚠️  Recommendation: Enable TLS 1.3 for better security{COLOR_RESET}")
    
    # Additional security context
    if not tls12_supported and not tls13_supported:
        print(f"\n{COLOR_RED}Warning: No modern TLS protocols detected! This could indicate:{COLOR_RESET}")
        print(f"  • A network connectivity issue")
        print(f"  • A misconfigured server")
        print(f"  • A security policy blocking the connection")
        print(f"\nTry using 'openssl s_client' to verify:")
        print(f"  openssl s_client -connect {hostname}:{port} -tls1_2")

def verify_cert_path():
    """Verify and fix SSL certificate path issues."""
    try:
        # Try to make a test HTTPS request
        requests.get('https://google.com', verify=True)
    except requests.exceptions.SSLError:
        # If SSL verification fails, try to use certifi's certificate bundle
        return certifi.where()
    return True

def check_common_vulnerabilities(hostname, port=443):
    """Check for common SSL/TLS vulnerabilities."""
    print(f"\n{COLOR_BOLD}Vulnerability Checks:{COLOR_RESET}")
    
    # Verify certificate path before making connections
    cert_path = verify_cert_path()
    
    try:
        context = ssl.create_default_context(cafile=cert_path if isinstance(cert_path, str) else None)
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                
                # Check TLS version
                if "TLSv1.0" in version or "TLSv1.1" in version:
                    print(f"{COLOR_YELLOW}⚠️ Warning: Server supports older TLS versions ({version}){COLOR_RESET}")
                else:
                    print(f"{COLOR_GREEN}✓ Server uses modern TLS versions ({version}){COLOR_RESET}")
                
                # Check cipher strength
                print(f"{COLOR_BOLD}Cipher Suite:{COLOR_RESET} {cipher[0]}")
                
                # Check for secure renegotiation
                if hasattr(ssock, 'get_secure_renegotiation_support'):
                    secure_reneg = ssock.get_secure_renegotiation_support()
                    if secure_reneg:
                        print(f"{COLOR_GREEN}✓ Secure renegotiation supported{COLOR_RESET}")
                    else:
                        print(f"{COLOR_YELLOW}⚠️ Warning: Secure renegotiation not supported{COLOR_RESET}")
                
    except ssl.SSLCertVerificationError as e:
        print(f"{COLOR_RED}Certificate verification failed: {e}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Tip: This might be due to a missing root certificate or an incomplete certificate chain.{COLOR_RESET}")
    except ConnectionRefused as e:
        print(f"{COLOR_RED}Connection refused: {e}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Tip: The server might not be accepting connections on port {port}.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}Error checking TLS version: {e}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Tip: Try updating your system's SSL certificates or using a different port.{COLOR_RESET}")

def check_server_health(hostname, port=443):
    """Check server health and response times."""
    print(f"\n{COLOR_BOLD}Server Health Check for {hostname}:{COLOR_RESET}")
    print("─" * 70)
    
    results = []
    
    # Test TCP connection time
    try:
        start_time = datetime.now()
        socket.create_connection((hostname, port), timeout=5)
        connection_time = (datetime.now() - start_time).total_seconds() * 1000
        results.append(("TCP Connection", True, f"{connection_time:.2f}ms"))
    except Exception as e:
        results.append(("TCP Connection", False, str(e)))
    
    # Test HTTPS response time
    try:
        start_time = datetime.now()
        response = requests.get(f"https://{hostname}", timeout=5, verify=True)
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        results.append(("HTTPS Response", True, f"{response_time:.2f}ms"))
        results.append(("HTTP Status", True, f"{response.status_code} {response.reason}"))
        
        # Check HTTP security headers
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'Content Type Options',
            'X-Frame-Options': 'Frame Options',
            'X-XSS-Protection': 'XSS Protection',
            'Content-Security-Policy': 'CSP'
        }
        
        for header, name in security_headers.items():
            if header in headers:
                results.append((f"{name}", True, headers[header]))
            else:
                results.append((f"{name}", False, "Not set"))
                
    except requests.exceptions.SSLError as e:
        results.append(("HTTPS Response", False, "SSL Error"))
    except requests.exceptions.RequestException as e:
        results.append(("HTTPS Response", False, str(e)))
    
    # Print results
    for test, success, details in results:
        if success:
            status = f"{COLOR_GREEN}✓{COLOR_RESET}"
            if isinstance(details, str) and "ms" in details:
                if float(details[:-2]) < 100:  # Less than 100ms
                    details = f"{COLOR_GREEN}{details}{COLOR_RESET}"
                elif float(details[:-2]) < 300:  # Less than 300ms
                    details = f"{COLOR_YELLOW}{details}{COLOR_RESET}"
                else:  # More than 300ms
                    details = f"{COLOR_RED}{details}{COLOR_RESET}"
        else:
            status = f"{COLOR_RED}✗{COLOR_RESET}"
        
        print(f"{status} {test:<20} │ {details}")
    
    print("─" * 70)

def check_certificate_transparency(hostname):
    """Check Certificate Transparency logs with enhanced analysis."""
    print(f"\n{COLOR_BOLD}Certificate Transparency Analysis for {hostname}:{COLOR_RESET}")
    print("─" * 70)
    
    # Define multiple CT log sources
    ct_sources = [
        {
            'name': 'crt.sh',
            'url': f"https://crt.sh/?q={hostname}&output=json",
            'timeout': 30
        },
        {
            'name': 'Google CT',
            'url': f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={hostname}",
            'timeout': 20
        }
    ]
    
    success = False
    
    for source in ct_sources:
        try:
            print(f"\nQuerying {source['name']}...")
            
            session = requests.Session()
            session.verify = certifi.where()
            
            # Configure retry strategy with longer backoff
            retries = requests.adapters.Retry(
                total=2,  # Reduced number of retries
                backoff_factor=2,  # Increased backoff time
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"]
            )
            adapter = requests.adapters.HTTPAdapter(max_retries=retries)
            session.mount('https://', adapter)
            
            response = session.get(
                source['url'],
                timeout=source['timeout'],
                headers={
                    'User-Agent': 'ChainCheck/1.0 Certificate Chain Validator',
                    'Accept': 'application/json'
                }
            )
            
            if response.status_code == 200:
                try:
                    certs = response.json()
                    if not certs:
                        print(f"{COLOR_YELLOW}No certificates found in CT logs{COLOR_RESET}")
                        return
                    
                    # Basic Statistics
                    print(f"\n{COLOR_BOLD}Overview:{COLOR_RESET}")
                    print(f"Total certificates found: {len(certs)}")
                    
                    # Group by issuer
                    issuers = {}
                    for cert in certs:
                        issuer = cert.get('issuer_name', 'Unknown')
                        if issuer not in issuers:
                            issuers[issuer] = []
                        issuers[issuer].append(cert)
                    
                    # Analyze patterns
                    print(f"\n{COLOR_BOLD}Certificate Patterns:{COLOR_RESET}")
                    print(f"Number of different issuers: {len(issuers)}")
                    
                    # Timeline Analysis
                    all_dates = []
                    for cert in certs:
                        not_before = cert.get('not_before')
                        if not_before:
                            try:
                                # Handle multiple date formats
                                if 'T' in not_before:
                                    # ISO format: '2017-08-09T00:00:00'
                                    parsed_date = datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%S')
                                else:
                                    # Standard format: '2017-08-09 00:00:00'
                                    parsed_date = datetime.strptime(not_before, '%Y-%m-%d %H:%M:%S')
                                all_dates.append(parsed_date)
                            except ValueError:
                                logging.debug(f"Could not parse date: {not_before}")
                                continue
                    
                    if all_dates:
                        first_cert = min(all_dates)
                        last_cert = max(all_dates)
                        print(f"\n{COLOR_BOLD}Timeline:{COLOR_RESET}")
                        print(f"First certificate: {first_cert.strftime('%Y-%m-%d')}")
                        print(f"Most recent certificate: {last_cert.strftime('%Y-%m-%d')}")
                        print(f"History length: {(last_cert - first_cert).days} days")
                    
                    # Detailed Issuer Analysis
                    print(f"\n{COLOR_BOLD}Issuer Details:{COLOR_RESET}")
                    for issuer, issuer_certs in issuers.items():
                        print(f"\n{COLOR_BLUE}Issuer:{COLOR_RESET} {issuer}")
                        print(f"Certificates issued: {len(issuer_certs)}")
                        
                        # Get the most recent cert with proper date parsing
                        try:
                            recent = max(issuer_certs, key=lambda x: datetime.strptime(
                                x.get('not_before', '2000-01-01T00:00:00').replace(' ', 'T'),
                                '%Y-%m-%dT%H:%M:%S'
                            ))
                            print(f"Most recent certificate:")
                            print(f"  Issued: {recent.get('not_before', 'Unknown')}")
                            print(f"  Expires: {recent.get('not_after', 'Unknown')}")
                        except (ValueError, TypeError):
                            print(f"  Could not determine most recent certificate")
                        
                        # Security Analysis
                        if len(issuer_certs) > 100:
                            print(f"{COLOR_YELLOW}⚠️  High number of certificates from this issuer{COLOR_RESET}")
                    
                    # Security Recommendations
                    print(f"\n{COLOR_BOLD}Security Analysis:{COLOR_RESET}")
                    if len(issuers) > 3:
                        print(f"{COLOR_YELLOW}⚠️  Multiple certificate authorities detected. Consider consolidating to fewer CAs.{COLOR_RESET}")
                    
                    recent_certs = [c for c in certs if c.get('not_before', '').startswith('2024')]
                    if len(recent_certs) > 10:
                        print(f"{COLOR_YELLOW}⚠️  High number of recent certificates. Monitor for unauthorized issuance.{COLOR_RESET}")
                    
                    print(f"\n{COLOR_BOLD}Monitoring Recommendations:{COLOR_RESET}")
                    print("• Regularly review new certificate issuances")
                    print("• Set up CT log monitoring for unauthorized certificates")
                    print("• Consider Certificate Authority Authorization (CAA) records")
                    
                    success = True
                    break  # Successfully got data, no need to try other sources
                    
                except ValueError as e:
                    print(f"{COLOR_RED}Error parsing {source['name']} response: {e}{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}Failed to query {source['name']} (Status: {response.status_code}){COLOR_RESET}")
        
        except requests.exceptions.Timeout:
            print(f"{COLOR_YELLOW}{source['name']} query timed out. Trying next source...{COLOR_RESET}")
        except requests.exceptions.RequestException as e:
            print(f"{COLOR_RED}Error accessing {source['name']}: {e}{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_RED}Unexpected error with {source['name']}: {e}{COLOR_RESET}")
    
    if not success:
        print(f"\n{COLOR_YELLOW}Unable to retrieve CT log information from any source.{COLOR_RESET}")
        print("This could be due to:")
        print("  • Rate limiting by CT log providers")
        print("  • Network connectivity issues")
        print("  • Service availability problems")
        print("\nTry again later or check the domain manually at:")
        print(f"  • https://crt.sh/?q={hostname}")
        print(f"  • https://transparencyreport.google.com/https/certificates")
    
    print("─" * 70)

def perform_security_scan(hostname, port=443):
    """Perform a comprehensive security scan."""
    print(f"\n{COLOR_BOLD}Comprehensive Security Scan for {hostname}:{COLOR_RESET}")
    print("─" * 70)
    
    try:
        # Check server health
        check_server_health(hostname, port)
        
        # Check SSL/TLS protocols
        check_ssl_protocols(hostname, port)
        
        # Check common vulnerabilities
        check_common_vulnerabilities(hostname, port)
        
        # Check Certificate Transparency
        check_certificate_transparency(hostname)
        
        # Additional security checks
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check certificate key size
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                    key_size = x509.get_pubkey().bits()
                    
                    print(f"\n{COLOR_BOLD}Additional Security Checks:{COLOR_RESET}")
                    if key_size >= 2048:
                        print(f"{COLOR_GREEN}✓ Certificate key size: {key_size} bits (Good){COLOR_RESET}")
                    else:
                        print(f"{COLOR_RED}✗ Certificate key size: {key_size} bits (Weak){COLOR_RESET}")
                    
                    # Check signature algorithm
                    sig_alg = x509.get_signature_algorithm().decode()
                    if 'sha256' in sig_alg or 'sha384' in sig_alg or 'sha512' in sig_alg:
                        print(f"{COLOR_GREEN}✓ Signature algorithm: {sig_alg} (Strong){COLOR_RESET}")
                    else:
                        print(f"{COLOR_RED}✗ Signature algorithm: {sig_alg} (Weak){COLOR_RESET}")
        
        except ssl.SSLCertVerificationError as e:
            print(f"\n{COLOR_RED}Certificate verification failed:{COLOR_RESET}")
            print(f"  • {str(e)}")
            print(f"{COLOR_YELLOW}This might be due to:{COLOR_RESET}")
            print("  • An incomplete or invalid certificate chain")
            print("  • A self-signed certificate")
            print("  • An expired certificate")
        except Exception as e:
            print(f"{COLOR_RED}Error performing additional security checks: {e}{COLOR_RESET}")
    
    except Exception as e:
        print(f"{COLOR_RED}Error during security scan: {e}{COLOR_RESET}")
    
    print("─" * 70)

# -----------------------------------
# 4. Interactive CLI
# -----------------------------------

def interactive_mode():
    """Enhanced interactive mode using Prompt Toolkit."""
    print(f"{COLOR_BOLD}Welcome to the SSL Chain Checker Interactive CLI{COLOR_RESET}")
    domain_completer = WordCompleter(['example.com', 'google.com', 'yourdomain.com'], ignore_case=True)
    
    PROMPT_STRING = "\n⚡ Enter choice (1-10): "  # Using a unicode character for style
    
    while True:
        print(f"\n{COLOR_BOLD}Available Options:{COLOR_RESET}")
        print("─" * 70)
        
        # Basic Certificate Operations
        print(f"{COLOR_BLUE}Certificate Chain Analysis:{COLOR_RESET}")
        print(f"  1. Fetch SSL Chain        │ Get complete certificate chain and validation status")
        print(f"  2. Save PEM Files         │ Export certificates to individual PEM files")
        print(f"  3. Export JSON Details    │ Save certificate details in structured JSON format")
        
        # Security Tests
        print(f"\n{COLOR_BLUE}Security Testing:{COLOR_RESET}")
        print(f"  4. Protocol Check         │ Test supported TLS versions and cipher suites")
        print(f"  5. Vulnerability Scan     │ Check for common SSL/TLS vulnerabilities")
        print(f"  6. Server Health          │ Test response times and security headers")
        
        # Advanced Analysis
        print(f"\n{COLOR_BLUE}Advanced Features:{COLOR_RESET}")
        print(f"  7. Certificate Logs       │ Search CT logs for historical certificates")
        print(f"  8. Full Security Scan     │ Comprehensive analysis of all security aspects")
        
        # Information
        print(f"\n{COLOR_BLUE}Help & Exit:{COLOR_RESET}")
        print(f"  9. About & Help           │ View features and usage information")
        print(f"  10. Exit                  │ Close the application")
        
        print("\n" + "─" * 70)
        
        user_choice = prompt(PROMPT_STRING)
        
        if user_choice == '1':
            print(f"\n{COLOR_YELLOW}Certificate Chain Analysis:{COLOR_RESET}")
            print("This will fetch and analyze the complete SSL/TLS certificate chain,")
            print("including validation status and expiration dates.")
            hostname = prompt("\nEnter domain (or 'exit' to quit): ", completer=domain_completer).strip()
            if hostname.lower() == 'exit':
                continue
                
            print(f"\n{COLOR_BOLD}Fetching SSL certificate chain for {hostname}...{COLOR_RESET}")
            cert_chain = get_certificate_chain(hostname)
            
            if cert_chain:
                display_certificate_chain(cert_chain, hostname)
                validate_certificate_chain(cert_chain)
                check_certificate_expiration(cert_chain)
                
                # Store the last checked domain and chain for other operations
                last_check = {'hostname': hostname, 'chain': cert_chain}
            else:
                print(f"{COLOR_RED}Failed to retrieve the certificate chain for {hostname}.{COLOR_RESET}")
                
        elif user_choice == '2':
            print(f"\n{COLOR_YELLOW}Save Certificates as PEM Files:{COLOR_RESET}")
            print("Export all certificates in the chain to individual PEM files")
            print("for use with other tools or manual inspection.")
            if 'last_check' in locals() and last_check['chain']:
                save_certificates_to_files(last_check['chain'], last_check['hostname'])
            else:
                print(f"{COLOR_YELLOW}Please fetch a certificate chain first (Option 1){COLOR_RESET}")
                
        elif user_choice == '3':
            print(f"\n{COLOR_YELLOW}Export Certificate Details to JSON:{COLOR_RESET}")
            print("Save detailed certificate information in JSON format")
            print("for integration with other tools or documentation.")
            if 'last_check' in locals() and last_check['chain']:
                export_chain_details_json(last_check['chain'], last_check['hostname'])
            else:
                print(f"{COLOR_YELLOW}Please fetch a certificate chain first (Option 1){COLOR_RESET}")
                
        elif user_choice == '4':
            print(f"\n{COLOR_YELLOW}SSL/TLS Protocol Analysis:{COLOR_RESET}")
            print("Check which SSL/TLS versions are supported and analyze")
            print("the security of available cipher suites.")
            hostname = prompt("\nEnter domain to check: ", completer=domain_completer).strip()
            if hostname:
                check_ssl_protocols(hostname)
                
        elif user_choice == '5':
            print(f"\n{COLOR_YELLOW}Vulnerability Scanner:{COLOR_RESET}")
            print("Check for common SSL/TLS vulnerabilities, insecure protocols,")
            print("and configuration issues.")
            hostname = prompt("\nEnter domain to check: ", completer=domain_completer).strip()
            if hostname:
                check_common_vulnerabilities(hostname)
                
        elif user_choice == '6':
            print(f"\n{COLOR_YELLOW}Server Health Check:{COLOR_RESET}")
            print("Analyze server response times, HTTP security headers,")
            print("and overall SSL/TLS configuration health.")
            hostname = prompt("\nEnter domain to check: ", completer=domain_completer).strip()
            if hostname:
                check_server_health(hostname)
        
        elif user_choice == '7':
            print(f"\n{COLOR_YELLOW}Certificate Transparency Log Analysis:{COLOR_RESET}")
            print("Search CT logs for historical certificates and analyze")
            print("certificate issuance patterns and potential security issues.")
            hostname = prompt("\nEnter domain to check: ", completer=domain_completer).strip()
            if hostname:
                check_certificate_transparency(hostname)
        
        elif user_choice == '8':
            print(f"\n{COLOR_YELLOW}Comprehensive Security Scan:{COLOR_RESET}")
            print("Perform a full security analysis including all available tests:")
            print("• Certificate validation")
            print("• Protocol security")
            print("• Server configuration")
            print("• Historical certificate analysis")
            print("• Vulnerability detection")
            hostname = prompt("\nEnter domain to check: ", completer=domain_completer).strip()
            if hostname:
                perform_security_scan(hostname)
        
        elif user_choice == '9':
            about_menu()
        
        elif user_choice == '10':
            print(f"\n{COLOR_GREEN}Thank you for using SSL Chain Checker!{COLOR_RESET}")
            break
        
        else:
            print(f"\n{COLOR_RED}Invalid choice. Please select an option between 1 and 10.{COLOR_RESET}")
        
        # Add a pause after each operation
        if user_choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
            input(f"\n{COLOR_BLUE}Press Enter to continue...{COLOR_RESET}")

# -----------------------------------
# 5. Main Function
# -----------------------------------

def main():
    parser = argparse.ArgumentParser(description='SSL Certificate Chain Checker')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('target', nargs='?', help='Domain or PEM file to check')
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
    elif args.target:
        hostname = args.target
        print(f"\n{COLOR_BOLD}Fetching SSL certificate chain for {hostname}...{COLOR_RESET}")
        cert_chain = get_certificate_chain(hostname)
        if cert_chain:
            display_certificate_chain(cert_chain, hostname)
            validate_certificate_chain(cert_chain)
            check_certificate_expiration(cert_chain)
        else:
            print(f"{COLOR_RED}Failed to retrieve the certificate chain for {hostname}.{COLOR_RESET}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
