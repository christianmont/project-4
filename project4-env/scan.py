import argparse
import json
import socket
# import ssl
import subprocess
import time
import requests

# Public DNS Resolvers (Hardcoded)
public_dns_resolvers = [
    '208.67.222.222',
    '1.1.1.1',
    '8.8.8.8',
    '8.26.56.26',
    '9.9.9.9',
    '64.6.65.6',
    '91.239.100.100',
    '185.228.168.168',
    '77.88.8.7',
    '156.154.70.1',
    '198.101.242.72',
    '176.103.130.130'
]

# TODO: FIX VIRTUAL ENVIRONMENT!!!
def scan_domain(domain):
    """
    Scans a given domain and returns a dictionary of results.
    """
    start_time = time.time()
    results = {"scan_time": start_time}

    '''
    # Scan for IPv4 addresses
    ipv4_addresses = get_ipv4_addresses(domain)
    results["ipv4_addresses"] = ipv4_addresses

    # Scan for IPv6 addresses
    ipv6_addresses = get_ipv6_addresses(domain)
    results["ipv6_addresses"] = ipv6_addresses

    # Scan for HTTP server
    http_server = get_http_server(domain)
    results["http_server"] = http_server
    

    # Scan for Insecure HTTP
    insecure_http = listens_unencrypted_http(domain)
    results["insecure_http"] = insecure_http'''

    # Scan for whether HTTP Strict Transport Security is enabled
    hsts = is_hsts_enabled(domain)
    results["hsts"] = hsts

    """
    # Scan for TLS versions
    tls_versions = get_tls_versions(domain)
    results["tls_versions"] = tls_versions
    """

    # Print the results
    print(f"Scanned {domain} in {time.time() - start_time} seconds")
    return results


def get_ipv4_addresses(domain):
    """
    Returns a list of all the IPv4 addresses associated with a domain,
    using a predefined list of hardcoded IP addresses.
    """
    # TODO: Edge cases for when dealing with canonical name, and when
    # non-authoritative answer is not part of the string
    ipv4_addresses = set()

    for dns_resolver in public_dns_resolvers:
        try:
            nslookup_result = subprocess.check_output(["nslookup", domain, dns_resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            # Isolates information about IPv4 and IPv6 addresses
            if f"{domain}\tcanonical name = " in nslookup_result:
                canonical_name_data = nslookup_result.split("Name:")[1].strip("\n\t")
                canonical_name = canonical_name_data.split("Address:")[0].strip(".\n\t")
                domain_address_info = nslookup_result.split(f"\nName:\t{canonical_name}\n")
            else:
                domain_address_info = nslookup_result.split(f"\nName:\t{domain}\n")

            for s in domain_address_info:
                if 'Address: ' in s:
                    ip = s.split('Address: ')[1].strip('\n\t')
                    if ':' not in ip:
                        ipv4_addresses.add(ip)
        except subprocess.TimeoutExpired:
            # TODO: Do we print here?
            print("TimeoutExpired Exception Occurred\n")
        except subprocess.CalledProcessError:
            print(f"Error with DNS Resolver {dns_resolver}")

    # print(ipv4_addresses)
    # TODO: Maybe return in specific order?
    return list(ipv4_addresses)

def get_ipv6_addresses(domain):
    """
    Returns a list of all the IPv6 addresses associated with a domain,
    using a predefined list of hardcoded IP addresses.
    """
    ipv6_addresses = set()

    for dns_resolver in public_dns_resolvers:
        try:
            nslookup_result = subprocess.check_output(["nslookup", "-type=AAAA", domain, dns_resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            if f"{domain}\tcanonical name = " in nslookup_result:
                canonical_name_data = nslookup_result.split("Name:")[1].strip("\n\t")
                canonical_name = canonical_name_data.split("Address:")[0].strip(".\n\t")
                domain_address_info = nslookup_result.split(f"\nName:\t{canonical_name}\n")
            else:
                domain_address_info = nslookup_result.split(f"\nName:\t{domain}\n")

            for s in domain_address_info:
                if 'Address: ' in s:
                    ip = s.split('Address: ')[1].strip('\n\t')
                    if ':' in ip:
                        ipv6_addresses.add(ip)
        except subprocess.TimeoutExpired:
            # TODO: Do we print here?
            print("TimeoutExpired Exception Occurred\n")
        except subprocess.CalledProcessError:
            print(f"Error with DNS Resolver {dns_resolver}")

    # TODO: Maybe return in specific order?
    return list(ipv6_addresses)

def get_http_server(domain):
    """
    Returns the name of the HTTP server software running on the domain.
    """
    # TODO: subprocess.DEVNULL?
    try:
        curl_result = subprocess.check_output(["curl", "-I", "-s", domain], timeout=2, stderr=subprocess.STDOUT)
        curl_result = curl_result.decode().lower()
        if "server:" in curl_result:
            server_index = curl_result.index("server:")
            server = curl_result[server_index + len("server:"):]
            server = server.split("\n")[0].strip()
            return server
        else:
            return None
    except subprocess.TimeoutExpired:
        print("TimeoutExpired Exception Occurred\n")

def listens_unencrypted_http(domain):
    """
    Returns a boolean indicating if the website listens for unencrytped
    HTTP requests on port 80
    """
    try:
        # Making an insecure HTTP request
        response = requests.get(f"http://{domain}", timeout=2)

        return response.status_code < 400
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.Timeout:
        print("Timeout Exception Occurred\n")

def redirects_to_https(domain):
    """
    Checks if unecrypted HTTP requests on port 80 are redirected to
    HTTPS requests on port 443.
    """
    try:
        # Making an insecure HTTP request
        response = requests.get(f"http://{domain}", timeout=2)

        for old_response in response.history:
            if str(old_response.status_code)[:2] == "30":
                redirect_location = old_response.headers['Location']
                if redirect_location[:len("https")] == "https":
                    return True

        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.Timeout:
        print("Timeout Exception Occurred\n")

def is_hsts_enabled(domain):
    """
    Checks if the given website has enabled HTTP Strict Transport
    Security.
    """
    try:
        # Making an insecure HTTP request
        response = requests.get(f"http://{domain}", timeout=2)

        header_fields = list(map(lambda s: s.lower(), response.headers.keys()))
        return "strict-transport-security" in header_fields
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.Timeout:
        print("Timeout Exception Occurred\n")

'''
def get_tls_versions(domain):
    """
    Returns a list of TLS versions supported by the domain.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.version()
    except:
        return []
'''

def scan_domains(domains):
    """
    Scans the specified domains and generates a report with the results.

    Arguments:
        domains: A list of domains to scan.

    Returns:
        A dictionary containing the scan results for the specified domains.
    """
    results = {}

    for domain in domains:
        # The time we began scanning the domain (in UNIX epoch seconds)
        start_time = time.time()
        print(f"Scanning {domain}...")

        '''
        ipv4_addresses = get_ipv4_addresses(domain)
        ipv6_addresses = get_ipv6_addresses(domain)
        http_server = get_http_server(domain)
        '''
        insecure_http = listens_unencrypted_http(domain)
        redirect_to_http = redirects_to_https(domain)
        hsts = is_hsts_enabled(domain)

        results[domain] = {
            "hsts": hsts
        }

        '''
        "scan_time": start_time,
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "http_server": http_server,
        "insecure_http": insecure_http,
        "redirect_to_http": redirect_to_http
        '''

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a list of web domains and output a JSON report.")
    parser.add_argument("input_file", help="Path to a file containing a list of domains to scan.")
    parser.add_argument("output_file", help="Path to the output file where the JSON report will be written.")
    args = parser.parse_args()

    with open(args.input_file, "r") as f:
        domains = [line.strip() for line in f]

    results = scan_domains(domains)

    with open(args.output_file, "w") as f:
        json.dump(results, f, sort_keys=True, indent=4)