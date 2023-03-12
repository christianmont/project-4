import argparse
import json
import socket
import ssl
import subprocess
import time

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

    # Scan for IPv4 addresses
    ipv4_addresses = get_ipv4_addresses(domain)
    results["ipv4_addresses"] = ipv4_addresses

    """
    # Scan for IPv6 addresses
    ipv6_addresses = get_ipv6_addresses(domain)
    results["ipv6_addresses"] = ipv6_addresses

    # Scan for HTTP server
    http_server = get_http_server(domain)
    results["http_server"] = http_server

    # Scan for TLS versions
    tls_versions = get_tls_versions(domain)
    results["tls_versions"] = tls_versions

    # Scan for TLS ciphers
    tls_ciphers = get_tls_ciphers(domain)
    results["tls_ciphers"] = tls_ciphers

    # Scan for WHOIS information
    whois_info = get_whois_info(domain)
    results["whois"] = whois_info

    # Scan for MX records
    mx_records = get_mx_records(domain)
    results["mx_records"] = mx_records

    # Scan for SPF records
    spf_records = get_spf_records(domain)
    results["spf_records"] = spf_records

    # Scan for TXT records
    txt_records = get_txt_records(domain)
    results["txt_records"] = txt_records

    # Print the results"""
    print(f"Scanned {domain} in {time.time() - start_time:.2f} seconds")
    return results


def get_ipv4_addresses(domain):
    """
    Returns a list of IPv4 addresses associated with a domain.
    """
    # TODO: Do this for every domain name resolver
    ipv4_addresses = []

    for dns_resolver in public_dns_resolvers:
        try:
            nslookup_result = subprocess.check_output(["nslookup", domain, dns_resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            # print(f"Current dns_resolver: {dns_resolver}")
            # print(f"nslookup_result: {nslookup_result}")

            domain_info = nslookup_result.split('Non-authoritative answer:')[1]
            # Isolates information about IPv4 and IPv6 addresses
            domain_address_info = domain_info.split(f"\nName:\t{domain}\n")

            for s in domain_address_info:
                if 'Address: ' in s:
                    ip = s.split('Address: ')[1].strip('\n\t')
                    if ':' not in ip:
                        ipv4_addresses.append(ip)
        except subprocess.TimeoutExpired:
            # TODO: Do we print here?
            print("TimeoutExpired Exception Occurred\n")

    # print(ipv4_addresses)
    return ipv4_addresses

def get_ipv6_addresses(domain):
    """
    Returns a list of IPv6 addresses associated with a domain.
    """
    # TODO: Do this for every domain name resolver
    ipv6_addresses = []

    for dns_resolver in public_dns_resolvers:
        try:
            nslookup_result = subprocess.check_output(["nslookup", domain, dns_resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            # print(f"Current dns_resolver: {dns_resolver}")
            # print(f"nslookup_result: {nslookup_result}")

            domain_info = nslookup_result.split('Non-authoritative answer:')[1]
            # Isolates information about IPv4 and IPv6 addresses
            domain_address_info = domain_info.split(f"\nName:\t{domain}\n")

            for s in domain_address_info:
                if 'Address: ' in s:
                    ip = s.split('Address: ')[1].strip('\n\t')
                    if ':' not in ip:
                        ipv4_addresses.append(ip)
        except subprocess.TimeoutExpired:
            # TODO: Do we print here?
            print("TimeoutExpired Exception Occurred\n")

    # print(ipv4_addresses)
    return ipv6_addresses

    '''
    try:
        return [ip[4][0] for ip in socket.getaddrinfo(domain, None, socket.AF_INET6)]
    except:
        return []
    '''

'''
def get_http_server(domain):
    """
    Returns the name of the HTTP server software running on the domain.
    """
    try:
        output = subprocess.check_output(["curl", "-I", "-s", domain], stderr=subprocess.DEVNULL)
        output = output.decode().lower()
        if "server:" in output:
            server_index = output.index("server:")
            server = output[server_index + 8:]
            server = server.split("\n")[0].strip()
            return server
    except:
        pass
    return ""


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


def get_tls_ciphers(domain):
    """
    Returns a list of TLS ciphers supported by the domain.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return [cipher[0] for cipher in ssock.shared_ciphers()]
    except:
        return []


def get_whois_info(domain):
    """
    Retrieves WHOIS information for the specified domain.

    Args:
        domain (str): The domain to retrieve WHOIS information for.

    Returns:
        dict: A dictionary containing WHOIS information for the specified domain.
    """
    try:
        whois_info = whois.whois(domain)

        if whois_info.status:
            status = whois_info.status[0].lower()
        else:
            status = ""

        if whois_info.creation_date:
            creation_date = whois_info.creation_date.strftime("%Y-%m-%d")
        else:
            creation_date = ""

        if whois_info.expiration_date:
            expiration_date = whois_info.expiration_date.strftime("%Y-%m-%d")
        else:
            expiration_date = ""

        return {
            "status": status,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": whois_info.name_servers,
            "registrar": whois_info.registrar,
            "whois_server": whois_info.whois_server
        }
    except Exception as e:
        print(f"Error getting WHOIS information for {domain}: {e}")
        return {}

def get_mx_records(domain):
    """
    This function returns a list of MX records for the domain.

    Args:
    - domain (str): the domain to retrieve MX records for.

    Returns:
    - mx_records (list): a list of MX records.
    """
    mx_records = []
    try:
        answers = dns.resolver.query(domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except Exception as e:
        print(e)
    return mx_records


def get_spf_records(domain):
    """
    This function returns a list of SPF records for the domain.

    Args:
    - domain (str): the domain to retrieve SPF records for.

    Returns:
    - spf_records (list): a list of SPF records.
    """
    spf_records = []
    try:
        answers = dns.resolver.query(domain, 'TXT')
        for rdata in answers:
            if rdata.to_text().startswith("v=spf"):
                spf_records.append(rdata.to_text().replace('"', ''))
    except Exception as e:
        print(e)
    return spf_records


def get_txt_records(domain):
    """
    This function returns a list of TXT records for the domain.

    Args:
    - domain (str): the domain to retrieve TXT records for.

    Returns:
    - txt_records (list): a list of TXT records.
    """
    txt_records = []
    try:
        answers = dns.resolver.query(domain, 'TXT')
        for rdata in answers:
            txt_records.append(rdata.to_text().replace('"', ''))
    except Exception as e:
        print(e)
    return txt_records
'''

def scan_domains(domains):
    """
    Scans the specified domains and generates a report with the results.

    Args:
        domains (list): A list of domains to scan.

    Returns:
        dict: A dictionary containing the scan results for the specified domains.
    """
    results = {}

    for domain in domains:
        # The time we began scanning the domain (in UNIX epoch seconds)
        start_time = time.time()
        print(f"Scanning {domain}...")

        ipv4_addresses = get_ipv4_addresses(domain)
        '''
        ipv6_addresses = get_ipv6_addresses(domain)
        http_server = get_http_server(domain)
        https_cert_info = get_https_cert_info(domain)
        whois_info = get_whois_info(domain)

        end_time = datetime.now().timestamp()
        '''

        results[domain] = {
            "scan_time": start_time,
            "ipv4_addresses": ipv4_addresses
        }

        '''
        "scan_time": start_time,
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "http_server": http_server,
        "https_cert_info": https_cert_info,
        "whois_info": whois_info,
        "total_scan_time": end_time - start_time
        '''

    return results


# TODO: Look into main.py being produced
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