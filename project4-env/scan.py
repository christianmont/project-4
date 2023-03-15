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
    results["insecure_http"] = insecure_http

    # Scan for whether HTTP Strict Transport Security is enabled
    hsts = is_hsts_enabled(domain)
    results["hsts"] = hsts

    # Scan for TLS versions
    tls_versions = get_tls_versions(domain)
    results["tls_versions"] = tls_versions

    # Scan for root certificate authority (CA)
    root_ca = get_root_ca(domain)
    results["root_ca"] = root_ca

    # Scan for reversed DNS names
    rdns_names = get_rdns_names(domain)
    results["rdns_names"] = rdns_names
    '''

    # Scan for the shortest and longest round trip time (RTT) observed
    # when contacting all the IPv4 addresses that were obtained for
    # a domain
    rtt_range = get_rtt_range(domain)
    results["rtt_range"] = rtt_range

    '''
    # Scan for all the real-world locations (city, province, country)
    # for all the IPv4 addresses that were obtained for a domain
    geo_locations = get_geo_locations(domain)
    results["geo_locations"] = geo_locations
    '''

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
    # TODO: subprocess.DEVNULL? Maybe consider moving decode?
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

def get_tls_versions(domain):
    """
    Returns a list of TLS versions supported by the domain.
    """
    # We can ignore SSLv2 and SSLv3
    possible_tls_versions = ['tls1', 'tls1_1', 'tls1_2', 'tls1_3']
    tls_to_official_name = {'tls1': "TLSv1.0", 'tls1_1': "TLSv1.1", 'tls1_2': "TLSv1.2", 'tls1_3': "TLSv1.3"}

    supported_tls_versions = []
    for tls_version in possible_tls_versions:
        try:
            subprocess.check_output(["openssl", "s_client", f"-{tls_version}", "-connect", f"{domain}:443"], input=b'', timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            supported_tls_versions.append(tls_to_official_name[tls_version])
        except subprocess.CalledProcessError:
            # TODO: Different error?
            print(f"{tls_version} not supported")
        except subprocess.TimeoutExpired:
            print("TimeoutExpired Exception Occurred\n")
    return supported_tls_versions

def get_root_ca(domain):
    """
    Gets the root certificate authority (CA) at the bottom of the chain
    of trust needed for validating the public key of the domain
    """
    try:
        openssl_result = subprocess.check_output(["openssl", "s_client", "-connect", f"{domain}:443"], input=b'', timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        if "Certificate chain" in openssl_result:
            certificate_index = openssl_result.index("Certificate chain")
            root_ca_data = openssl_result[certificate_index + len("Certificate chain"):]

            separator_index = root_ca_data.index("---")
            root_ca_data = root_ca_data[:separator_index]
            root_ca_data = root_ca_data.strip('\n').split('\n')[-1].strip()
            
            root_ca_start_index = root_ca_data.index("O = ") + len("O = ")
            root_ca_data = root_ca_data[root_ca_start_index:]

            cn_index = ou_index = float('inf')
            if ", CN = " in root_ca_data:
                cn_index = root_ca_data.index(", CN = ")
            if ", OU = " in root_ca_data:
                ou_index = root_ca_data.index(", OU = ")
            root_ca_end_index = min(cn_index, ou_index)
            return root_ca_data[:root_ca_end_index].strip('\"\'')
    except subprocess.CalledProcessError:
        print("CalledProcessError Occurred\n")
    except subprocess.TimeoutExpired:
        print("TimeoutExpired Exception Occurred\n")

def get_rdns_names(domain):
    """
    Get the reverse DNS names for the IPv4 addresses.
    """
    rdns_names = set()
    ipv4_addresses = get_ipv4_addresses(domain)
    for ipv4_address in ipv4_addresses:
        try:
            nslookup_result = subprocess.check_output(["nslookup", "-type=PTR", ipv4_address], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            if 'Non-authoritative answer:\n' in nslookup_result and 'Authoritative answers can be found from:\n' in nslookup_result:
                nonauthoritative_index = nslookup_result.index('Non-authoritative answer:\n') + len('Non-authoritative answer:\n')
                authoritative_index = nslookup_result.index('Authoritative answers can be found from:\n')

                name_data = nslookup_result[nonauthoritative_index:authoritative_index].strip('\n').split('\n')
            else:
                name_data = []
                for line in nslookup_result.split('\n'):
                    if "\tname = " in line:
                        name_data.append(line)

            for name_data_line in name_data:
                rdns_name_index = name_data_line.index("name = ") + len("name = ")
                rdns_name = name_data_line[rdns_name_index:-1]
                rdns_names.add(rdns_name)
        except subprocess.CalledProcessError:
            print("CalledProcessError Occurred\n")
        except subprocess.TimeoutExpired:
            print("CalledProcessError Occurred\n")
    return list(rdns_names)

def get_rtt_range(domain):
    """
    Gets the shortest and longest round trip time (RTT) observed when
    contacting all the IPv4 addresses that were collected for the
    specified domain.
    """
    ipv4_addresses = get_ipv4_addresses(domain)
    common_ports = ["80", "22", "443"]
    rtt_list = []
    for port in common_ports:
        for ipv4_address in ipv4_addresses:
            try:
                telnet_output = subprocess.check_output(["sh",  "-c", f"time echo -e '\x1dclose\x0d' | telnet {ipv4_address} {port}"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                real_time_start_index = telnet_output.index("real\t0m") + len("real\t0m")
                time_data = telnet_output[real_time_start_index:]
                real_time_end_index = time_data.index('s')
                real_time = time_data[:real_time_end_index]
                rtt_list.append(float(real_time))
            except subprocess.TimeoutExpired:
                pass
            except subprocess.CalledProcessError:
                print("CalledProcessError Occurred\n")
        # RTT should be about the same on all ports
        if len(ipv4_addresses) > 0:
            break
            
    if len(rtt_list) == 0:
        return None
    return [int(min(rtt_list) * 1000), int(max(rtt_list) * 1000)]

def get_geo_locations(domain):
    """
    Gets all the real-world locations (city, province, country) for the
    IPv4 addresses that were collected for the specified domain
    """
    '''
    try:
    except:
    except:
                except subprocess.CalledProcessError:
            print("CalledProcessError Occurred\n")
    return
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
        insecure_http = listens_unencrypted_http(domain)
        redirect_to_http = redirects_to_https(domain)
        hsts = is_hsts_enabled(domain)
        tls_versions = get_tls_versions(domain)
        root_ca = get_root_ca(domain)
        rdns_names = get_rdns_names(domain)
        geo_locations = get_geo_locations(domain)
        '''
        rtt_range = get_rtt_range(domain)

        results[domain] = {
            "rtt_range": rtt_range
        }

        '''
        "scan_time": start_time,
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "http_server": http_server,
        "insecure_http": insecure_http,
        "redirect_to_http": redirect_to_http
        "hsts": hsts,
        "tls_versions": tls_versions,
        "root_ca": root_ca,
        "rdns_names": rdns_names,
        "geo_locations": geo_locations
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