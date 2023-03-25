#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import socket
import csv
import functools
import concurrent.futures
import datetime

import code
import pprint

from datetime import datetime, timezone
from w3lib.url import safe_url_string
import cymruwhois
import pandas as pd
import validators

# Script version
VERSION = '1.0'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
parser.add_argument('-i', '--input-file', help='Input file as a list of newline-separated FQDN', default = None)
#input_group.add_argument('-r', '--refresh', help='Take an existing CSV output file and refresh records', default = None)
parser.add_argument('-o', '--output-file', help='CSV output file (default: ./resolve_output.csv)', default = os.path.abspath(os.path.join(os.getcwd(), 'resolve_output.csv')))

def resolve_ipv4(fqdn):
    try:
        res_ipv4 = socket.gethostbyname(fqdn)
    except:
        res_ipv4 = None
    finally:
        return res_ipv4

def resolve_ipv6(fqdn):
    try:
        res_ipv6 = socket.getaddrinfo(fqdn, None, socket.AF_INET6)[0][4][0]
    except:
        res_ipv6 = None
    finally:
        return res_ipv6

def check_entry_type(entry):
    entry = entry.strip()
    entry_idna_decoded = safe_url_string(entry)
    
    if validators.domain(entry):
        return entry_idna_decoded, resolve_ipv4(entry), resolve_ipv6(entry) 
    
    elif validators.ip_address.ipv4(entry):
        return entry_idna_decoded, resolve_ipv4(entry), None
    
    elif validators.ip_address.ipv6(entry):
        return entry_idna_decoded, None, resolve_ipv6(entry)

def resolve(options):
    results = pd.DataFrame(columns=['time_checked', 'netloc', 'netloc_idna_decoded', 'ipv4', 'ipv4_asn', 'ipv4_prefix', 'ipv4_owner', 'ipv4_cc', 'ipv6', 'ipv6_asn', 'ipv6_prefix', 'ipv6_owner', 'ipv6_cc'])
    
    with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
        data = fd_input.read().splitlines()
    
    print("[+] %s entries in the output file '%s'" % (len(data), options.input_file))
    
    time_checked = datetime.now(timezone.utc).isoformat()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (netloc, executor.submit(functools.partial(check_entry_type, netloc)))
                for netloc in data ]
    
    for netloc, entry_resolved in futs:
        netloc_idna_decoded, ipv4, ipv6 = entry_resolved.result()
        if netloc not in results.netloc:
            results.loc[len(results), 'netloc'] = netloc
            results.loc[results.netloc.eq(netloc), 'time_checked'] = time_checked
            results.loc[results.netloc.eq(netloc), 'netloc_idna_decoded'] = netloc_idna_decoded
            if ipv4:
                results.loc[results.netloc.eq(netloc), 'ipv4'] = ipv4
            if ipv6:
                results.loc[results.netloc.eq(netloc), 'ipv6'] = ipv6

    cymru_resolver = cymruwhois.Client()
    cymru_lookup = cymru_resolver.lookupmany_dict(results.ipv4.dropna().unique().tolist() + results.ipv6.dropna().unique().tolist())
    cymru_resolver.disconnect()
    
    for cymru_result in cymru_lookup.keys():
        elem = vars(cymru_lookup[cymru_result])
        if validators.ip_address.ipv4(cymru_result):
            results.loc[results.ipv4.eq(cymru_result), 'ipv4_asn'] = elem['asn']
            results.loc[results.ipv4.eq(cymru_result), 'ipv4_prefix'] = elem['prefix']
            results.loc[results.ipv4.eq(cymru_result), 'ipv4_owner'] = elem['owner']
            results.loc[results.ipv4.eq(cymru_result), 'ipv4_cc'] = elem['cc']
            
        elif validators.ip_address.ipv6(cymru_result):
            results.loc[results.ipv6.eq(cymru_result), 'ipv6_asn'] = elem['asn']
            results.loc[results.ipv6.eq(cymru_result), 'ipv6_prefix'] = elem['prefix']
            results.loc[results.ipv6.eq(cymru_result), 'ipv6_owner'] = elem['owner']
            results.loc[results.ipv6.eq(cymru_result), 'ipv6_cc'] = elem['cc']
    
    results.to_csv(options.output_file, sep=';', index=False, quoting=csv.QUOTE_ALL, lineterminator='\n')
    print("[+] %s entries written to output file '%s'" % (len(results), options.output_file))
    
    return
    
def main():
    global parser
    options = parser.parse_args()
    resolve(options)
    return
    
if __name__ == "__main__" :
    main()