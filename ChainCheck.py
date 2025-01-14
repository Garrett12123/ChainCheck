# SSL Chain Checker with Interactive CLI and Enhancements

# -----------------------------------
# 1. Import Libraries
# -----------------------------------
import os
import sys
import socket
import logging
import datetime
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
    today = datetime.datetime.now(datetime.timezone.utc)
    for idx, cert_pem in enumerate(cert_chain_pem):
        cert = asn1_x509.Certificate.load(ssl.PEM_cert_to_DER_cert(cert_pem))
        not_after = cert['tbs_certificate']['validity']['not_after'].native
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        days_to_expire = (not_after - today).days
        if days_to_expire < 0:
            print(f"{COLOR_RED}Certificate {idx} has expired on {not_after.strftime('%Y-%m-%d')}!{COLOR_RESET}")
        elif days_to_expire < warning_days:
            print(f"{COLOR_YELLOW}Certificate {idx} will expire in {days_to_expire} days on {not_after.strftime('%Y-%m-%d')}.{COLOR_RESET}")
        else:
            print(f"{COLOR_GREEN}Certificate {idx} is valid until {not_after.strftime('%Y-%m-%d')} ({days_to_expire} days left).{COLOR_RESET}")

def about_menu():
    """Display an about menu with usage information."""
    print(f"{COLOR_BOLD}About SSL Chain Checker{COLOR_RESET}")
    print(f"{COLOR_GREEN}This tool fetches and validates SSL/TLS certificate chains.{COLOR_RESET}")
    print(f"{COLOR_YELLOW}Features include:{COLOR_RESET}")
    print("  1. Fetching certificate chains from specified domains.")
    print("  2. Validating chain order and integrity.")
    print("  3. Checking for certificate expiration.")
    print("  4. Displaying detailed certificate information, including SAN entries.")
    print("  5. Interactive mode with domain autocompletion.")
    print(f"{COLOR_BLUE}Use this tool to troubleshoot SSL certificate issues and ensure proper configuration.{COLOR_RESET}\n")

# -----------------------------------
# 4. Interactive CLI
# -----------------------------------

def interactive_mode():
    """Interactive mode using Prompt Toolkit."""
    print(f"{COLOR_BOLD}Welcome to the SSL Chain Checker Interactive CLI{COLOR_RESET}")
    domain_completer = WordCompleter(['example.com', 'google.com', 'yourdomain.com'], ignore_case=True)
    while True:
        print(f"\n{COLOR_BOLD}Options:{COLOR_RESET}")
        print(f"  1. Enter domain to fetch SSL chain")
        print(f"  2. About this tool")
        print(f"  3. Exit")
        user_choice = prompt("Choose an option: ")
        if user_choice == '1':
            user_input = prompt("Enter domain (or 'exit' to quit): ", completer=domain_completer)
            if user_input.lower() == 'exit':
                print("Exiting to main menu.")
                continue
            if user_input:
                hostname = user_input.strip()
                print(f"\n{COLOR_BOLD}Fetching SSL certificate chain for {hostname}...{COLOR_RESET}")
                cert_chain = get_certificate_chain(hostname)

                if cert_chain:
                    display_certificate_chain(cert_chain, hostname)
                    validate_certificate_chain(cert_chain)
                    check_certificate_expiration(cert_chain)
                else:
                    print(f"{COLOR_RED}Failed to retrieve the certificate chain for {hostname}.{COLOR_RESET}")
        elif user_choice == '2':
            about_menu()
        elif user_choice == '3':
            print("Exiting interactive mode.")
            break
        else:
            print(f"{COLOR_RED}Invalid choice. Please try again.{COLOR_RESET}")

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
