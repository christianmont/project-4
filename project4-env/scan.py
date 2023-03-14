import argparse
import json
import socket
import ssl
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
    '''

    # Scan for Insecure HTTP
    insecure_http = listens_unencrypted_http(domain)
    results["insecure_http"] = insecure_http

    """
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
    Returns a list of IPv6 addresses associated with a domain.
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
        output = subprocess.check_output(["curl", "-I", "-s", domain], timeout=2, stderr=subprocess.STDOUT)
        output = output.decode().lower()
        if "server:" in output:
            server_index = output.index("server:")
            server = output[server_index + 8:]
            server = server.split("\n")[0].strip()
            return server
        else:
            return None
    except subprocess.TimeoutExpired:
        print("TimeoutExpired Exception Occurred\n")
    return ""

def listens_unencrypted_http(domain):
    """
    Returns a boolean indicating if the website listens for unencrytped
    HTTP requests on port 80
    """
    # TODO: Check if this works 100%
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to domain on port 80
    try:
        s.connect((domain, 80))
        return True
    except:
        return False

def redirects_to_https(domain):
    """
    Checks if unecrypted HTTP requests on port 80 are redirected to
    HTTPS requests on port 443.
    """
    # TODO: Maybe call listens_unecrypted_http
    # TODO: Ensure that websites that are given to us do not indicate
    # HTTP or HTTPS

    # Making an insecure HTTP request
    request = requests.get(f"http://{domain}")

    # return 
    print(type(request.history[0]))
    return True

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

        '''
        ipv4_addresses = get_ipv4_addresses(domain)
        ipv6_addresses = get_ipv6_addresses(domain)
        http_server = get_http_server(domain)
        '''
        insecure_http = listens_unencrypted_http(domain)
        redirect_to_http = redirects_to_https(domain)
        '''
        https_cert_info = get_https_cert_info(domain)
        whois_info = get_whois_info(domain)

        end_time = datetime.now().timestamp()
        '''

        results[domain] = {
            "insecure_http": insecure_http,
            "redirect_to_http": redirect_to_http
        }

        '''
        "scan_time": start_time,
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "http_server": http_server,
        "insecure_http": insecure_http,
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