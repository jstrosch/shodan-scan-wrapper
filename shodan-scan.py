#!/usr/bin/env python

__author__ = "Josh Stroschein"
__version__ = "0.0.1"
__maintainer__ = "Josh Stroschein"

import sys,re,subprocess,optparse

""" Sample Response Returned from Shodan from domain search
BUNDLESBYB.COM
        NS     ns33.domaincontrol.com
        NS     ns34.domaincontrol.com
        A      45.56.101.4
        TXT    v=spf1 include:spf.protection.outlook.com -all
        TXT    NETORGFT4093819.onmicrosoft.com
        SOA    ns33.domaincontrol.com
        MX     bundlesbyb-com.mail.protection.outlook.com
"""

# IPv4 with port
#ipv4 = re.compile(r"^.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,6}).*$")
# IPv4 without port
ipv4 = re.compile(r"^.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$", re.MULTILINE|re.DOTALL)

def setup_args():

    parser = optparse.OptionParser()

    parser.add_option('-f', '--file',
    action="store", dest="file",
    help="File that contains domains")

    parser.add_option('-d', '--domain',
    action="store", dest="target_domain",
    help="Domain to scan")

    return parser.parse_args()

def print_header(msg):
    print("*" * 25 + " " + msg + " " + "*" * 25 + "\n")

def main(argv):

    print_header("Starting to gather scan results")

    options, args = setup_args()

    domains = []
    no_ip_domains = []
    ip_domains = {}

    if options.target_domain:
        domains.append(options.target_domain)
    elif options.file:
        with open(options.file) as configs:
            content = configs.readlines()
            for line in content:
                if line not in domains:
                    domains.append(line)
    print("[*] Found %d unique domain(s)" % len(domains))

    for domain in domains:
        print("[?] Searching Shodan for %s" % domain)
        process_object = subprocess.Popen(['shodan', 'domain',domain],stdout=subprocess.PIPE , stderr = subprocess.STDOUT)
        scan_results = process_object.stdout.read().decode('UTF-8')

        if ipv4.match(scan_results):
            result = ipv4.search(scan_results).group(1)
            ip_domains[domain] = result
            print("[*] Found IP for domain %s" % result)
        else:
            print("[X] No IP Found for domain %s" % domain)
            no_ip_domains.append(domain)

    print("[*] Found %d IP/domains" % len(ip_domains))
    print("[!] Missing %d IP/domains" % len(no_ip_domains))
    print_header("Scanning Started")

    for domain in ip_domains:
        print("[!] Scanning %s" % domain)
        process_object = subprocess.Popen(['shodan', 'host',ip_domains[domain]],stdout=subprocess.PIPE , stderr = subprocess.STDOUT)
        scan_results = process_object.stdout.read().decode('UTF-8')
        print(scan_results + "\n\n")
    
    print_header("Overall Results")
    print("[*] IPs that were scanned")
    for domain in ip_domains:
        print("%s" % ip_domains[domain])
    print("\n[*] No IP was obtained from Shodan")
    for ip in no_ip_domains:
        print("%s" % ip)    

if __name__ == '__main__':
	main(sys.argv[1:])