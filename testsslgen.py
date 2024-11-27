import json
import sys

def parse_ssl_results(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Extract server info
    server_info = data.get('server_info', {})
    hostname = server_info.get('hostname', 'N/A')
    ip_address = server_info.get('ip', 'N/A')
    port = server_info.get('port', 'N/A')

    print(f"Server Info:")
    print(f"  Hostname: {hostname}")
    print(f"  IP Address: {ip_address}")
    print(f"  Port: {port}")
    print()

    # Extract scan results
    scan_results = data.get('scan_commands_results', {})

    # Example: Extract certificate info
    cert_info = scan_results.get('certificate_info', {}).get('certificate_deployments', [])
    for cert in cert_info:
        print("Certificate Info:")
        print(f"  Subject: {cert.get('leaf_certificate_subject', 'N/A')}")
        print(f"  Valid From: {cert.get('leaf_certificate_validity', {}).get('not_before', 'N/A')}")
        print(f"  Valid Until: {cert.get('leaf_certificate_validity', {}).get('not_after', 'N/A')}")
        print()

    # Example: Check for Heartbleed vulnerability
    heartbleed = scan_results.get('heartbleed', {})
    heartbleed_result = heartbleed.get('is_vulnerable_to_heartbleed', False)
    print(f"Heartbleed Vulnerable: {heartbleed_result}")

    # Example: Extract TLS 1.3 cipher suites
    tlsv1_3 = scan_results.get('tlsv1_3', {})
    cipher_suites = tlsv1_3.get('accepted_cipher_suites', [])
    print("TLS 1.3 Cipher Suites:")
    for suite in cipher_suites:
        print(f"  - {suite.get('name', 'N/A')}")

    print()

    # Example: Extract TLS 1.2 cipher suites
    tlsv1_2 = scan_results.get('tlsv1_2', {})
    cipher_suites = tlsv1_2.get('accepted_cipher_suites', [])
    print("TLS 1.2 Cipher Suites:")
    for suite in cipher_suites:
        print(f"  - {suite.get('name', 'N/A')}")

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python testsslgen.py <json_file>")
        sys.exit(1)

    json_file = sys.argv[1]
    parse_ssl_results(json_file)
