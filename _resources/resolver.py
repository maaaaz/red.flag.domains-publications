#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import csv
import functools
import concurrent.futures
import datetime
import urllib.parse
import json

import code
import pprint

import dns.resolver
from datetime import datetime, timezone
from w3lib.url import safe_url_string
import cymruwhois
import pandas as pd
import validators


# Script version
VERSION = '1.1'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)

input_group = parser.add_argument_group('Raw or CSV input parameters')
input_group = input_group.add_mutually_exclusive_group()
input_group.add_argument('-i', '--input-file', help='Input file as a list of newline-separated FQDN', default = None)
input_group.add_argument('-r', '--refresh-file', help='Take an existing CSV output file and refresh records', default = None)

zdns_group = parser.add_argument_group('ZDNS input parameters: no resolve, just taking zdns A and AAAA results and produce the CSV output file')
zdns_group.add_argument('-z', '--zdns-outfile', help='zdns output results', default = None)

output_group = parser.add_argument_group('CSV output parameters')
output_group.add_argument('-o', '--output-file', help='CSV output file (default: ./resolve_output.csv)', default = os.path.abspath(os.path.join(os.getcwd(), 'resolve_output.csv')))

def decode_idna(entry):
    if validators.url(entry):
        return urllib.parse.urlparse(safe_url_string(entry)).netloc
    
    elif validators.domain(entry):
        return urllib.parse.urlparse(safe_url_string('http://'+entry)).netloc

def resolve_entry(netloc):
    ipv4 = None
    ipv6 = None
    
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['9.9.9.9', '149.112.112.112', '1.1.1.1', '8.8.8.8', '1.0.0.1', '208.67.222.222', '208.67.220.123']
    resolver.timeout = 0.3
    
    # IPv4 resolve
    try:
        ipv4_response = resolver.resolve(netloc, 'A')
        if ipv4_response:
            ipv4 = ipv4_response[0].to_text()
    except:
        pass
    
    # IPv6 resolve
    try:
        ipv6_response = resolver.resolve(netloc, 'AAAA')
        if ipv6_response:
            ipv6 = ipv6_response[0].to_text()
    except:
        pass
    
    finally:
        return ipv4, ipv6

def check_entry_type(entry):
    #print("[+] resolving '%s'" % entry)
    entry = entry.strip()
    
    netloc = None
    netloc_idna_decoded = None
    netloc_ipv4 = None
    netloc_ipv6 = None
    
    if validators.url(entry) or validators.domain(entry):
        if validators.url(entry):
            netloc = urllib.parse.urlparse(entry).netloc
            netloc_idna_decoded = decode_idna(entry)
        
        elif validators.domain(entry):
            netloc = entry
            netloc_idna_decoded = decode_idna(entry)
            
        netloc_ipv4, netloc_ipv6 = resolve_entry(netloc_idna_decoded)
        
    elif validators.ip_address.ipv4(entry):
        netloc = netloc_idna_decoded = entry
        netloc_ipv4 = entry
        
    elif validators.ip_address.ipv6(entry):
        netloc = netloc_idna_decoded = entry
        netloc_ipv6 = entry
    
    #print(netloc_idna_decoded, netloc, netloc_ipv4, netloc_ipv6)
    return netloc_idna_decoded, netloc, netloc_ipv4, netloc_ipv6

def csv_output(results, options):
    final_results = results.sort_values(by='netloc_idna_decoded').reset_index(drop=True)
    final_results.to_csv(options.output_file, sep=';', index=False, quoting=csv.QUOTE_ALL, lineterminator='\n')
    
    time_checked_end = datetime.now(timezone.utc).isoformat()
    print("\n[+] end of process at:\t\t\t\t'%s'" % (time_checked_end))
    print("[+] %s entries written to output file '%s'" % (len(results), options.output_file))

def cymru_resolve(results, options):
    print("\n[+] starting to resolve cymru at:\t\t'%s'" % (datetime.now(timezone.utc).isoformat()))
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
    
    print("[+] stopped cymru resolve at:\t\t\t'%s'" % (datetime.now(timezone.utc).isoformat()))
    
    csv_output(results, options)
    
    return

def process_raw_input(results, options):
    with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
        data = fd_input.read().splitlines()
    
    print("[+] processing raw file '%s' %s entries " % (options.input_file, len(data)))
    
    time_checked = datetime.now(timezone.utc).isoformat()
    print("\n[+] starting to resolve DNS at:\t\t\t'%s'" % (time_checked))
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (netloc, executor.submit(functools.partial(check_entry_type, netloc)))
                for netloc in data if netloc ]
    
    for netloc, entry_resolved in futs:
        if entry_resolved.result():
            netloc_idna_decoded, netloc_in, netloc_ipv4, netloc_ipv6 = entry_resolved.result()
            if netloc_in not in results.netloc:
                results.loc[len(results), 'netloc'] = netloc_in
                results.loc[results.netloc.eq(netloc_in), 'time_checked'] = time_checked
                results.loc[results.netloc.eq(netloc_in), 'netloc_idna_decoded'] = netloc_idna_decoded
                if netloc_ipv4:
                    results.loc[results.netloc.eq(netloc_in), 'ipv4'] = netloc_ipv4
                if netloc_ipv6:
                    results.loc[results.netloc.eq(netloc_in), 'ipv6'] = netloc_ipv6
    
    cymru_resolve(results, options)
    
    return
    

def process_zdns_input(results, options):
    print("[+] processing zdns file: '%s'" % options.zdns_outfile)
    print("\n[+] starting to insert zdns results at:\t\t'%s'" % datetime.now(timezone.utc).isoformat())
    
    with open(options.zdns_outfile, mode='r', encoding='utf-8') as fd_input:
        for count, line in enumerate(fd_input):
            data = json.loads(line)
            
            #print('[+] count %s' % count) if (count % 1000 == 0) else None
            
            if 'name' in data:
                netloc_in = data['name']
                
                if not(results.netloc.isin([netloc_in]).any()):
                    results.loc[len(results), 'netloc'] = netloc_in
                
                results.loc[results.netloc.eq(netloc_in), 'netloc_idna_decoded'] = decode_idna(netloc_in)
                
                if ('timestamp' in data) and (results.loc[results.netloc.eq(netloc_in), 'time_checked'].isnull().any()):
                    results.loc[results.netloc.eq(netloc_in), 'time_checked'] = data['timestamp']
                
                if 'data' in data:
                    if 'answers' in data['data']:
                        # resolution successful
                        for answer in data['data']['answers']:
                            if (answer['name'].lower() == netloc_in.lower()) and answer['answer']:
                                if (answer['type'] == 'A') and (results.loc[results.netloc.eq(netloc_in), 'ipv4'].isnull().any()):
                                    results.loc[results.netloc.eq(netloc_in), 'ipv4'] = answer['answer']
                                
                                elif (answer['type'] == 'AAAA') and (results.loc[results.netloc.eq(netloc_in), 'ipv6'].isnull().any()):
                                    results.loc[results.netloc.eq(netloc_in), 'ipv6'] = answer['answer']
    
    print("[+] stopped inserting zdns results at:\t\t'%s'" % datetime.now(timezone.utc).isoformat())
    cymru_resolve(results, options)
    
    return

def main():
    global parser
    options = parser.parse_args()
    
    results = pd.DataFrame(columns=['time_checked', 'netloc_idna_decoded', 'netloc', 'ipv4', 'ipv4_asn', 'ipv4_prefix', 'ipv4_owner', 'ipv4_cc', 'ipv6', 'ipv6_asn', 'ipv6_prefix', 'ipv6_owner', 'ipv6_cc'])
    
    if options.input_file:
        process_raw_input(results, options)
    
    elif options.zdns_outfile:
        process_zdns_input(results, options)
        
    
    return
    
if __name__ == "__main__" :
    main()