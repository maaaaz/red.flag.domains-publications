#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import functools
import concurrent.futures
import requests
import time

import code
import pprint

from w3lib.url import safe_url_string
import validators
import jmespath

# Script version
VERSION = '1.1'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
common_group = parser.add_argument_group('common parameters')
common_group.add_argument('-a', '--action', help = 'Action to do on Netcraft (default \'submit\')', choices = ['submit', 'check'], type=str.lower, default = 'submit')
common_group.add_argument('-i', '--input-file', help='Input file (either list of newline-separated FQDN or URL (for reporting) || submission UUID (for checking reports)', required = True)

action_check_group = parser.add_argument_group("'check' action parameters")
action_check_group.add_argument('-w', '--workers', help='Number of multithread workers (default 8)', default=8, type=int)
action_check_group.add_argument('-o', '--output', help='Output file for all malicious findings (default: ./output_malicious.txt)', default = os.path.abspath(os.path.join(os.getcwd(), 'output_malicious.txt')))
action_check_group.add_argument('-oc', '--output-credited', help='Output file for credited malicious findings only (default: ./output_malicious_credited.txt)', default = os.path.abspath(os.path.join(os.getcwd(), 'output_malicious_credited.txt')))


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def add_entries_to_results(entries, results):
    for entry in entries:
        if not(entry in results):
            results.append(entry)

def dump_to_file(filename, content):
    with open(filename, mode='w', encoding='utf-8') as fd_out:
        for entry in content:
            entry = entry.strip()
            fd_out.write(entry + "\n")

def get_sub_results(ref):
    res = False
    malicious_all = []
    malicious_credited = []
    
    url_endpoint = "https://report.netcraft.com/api/v3/submission/%s/urls"
    
    req = requests.get(url_endpoint % ref)
    if req.ok:
        res = True
        
        req_json = req.json()
        #print("[+] Netcraft check request successful")
        current_malicious = jmespath.search("urls[?url_state=='malicious'].url", req_json)
        malicious_all = malicious_all + current_malicious
        
        current_credited = jmespath.search("urls[?url_state=='malicious' && tags[?name=='credited']].url", req_json)
        malicious_credited = malicious_credited + current_credited
    
    else:
        print("[!] error while checking Netcraft ref")
        pprint.pprint(req.status_code)
        print(req.content)
    
    return res, malicious_all, malicious_credited

def netcraft_check(options):
    retval = os.EX_OK
    
    refs = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            refs = fd_input.read().splitlines()
        
        if refs:
            malicious_all = []
            malicious_credited = []
            
            print("[+] Number of submission UUIDs found: %s\n" % len(refs))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as executor:
                futs = [ (ref, executor.submit(functools.partial(get_sub_results, ref))) for ref in refs ]
            
            for ref, fut in futs:
                res, current_malicious_all, current_malicious_credited = fut.result()
                add_entries_to_results(current_malicious_all, malicious_all)
                add_entries_to_results(current_malicious_credited, malicious_credited)
            
            print("[+] Number of all malicious: %s" % len(malicious_all))
            pprint.pprint(malicious_all)
            print("\n-------------------\n")
            
            print("[+] Number of credited malicious: %s" % len(malicious_credited))
            pprint.pprint(malicious_credited)
            
            dump_to_file(options.output, malicious_all)
            dump_to_file(options.output_credited, malicious_credited)
            
        else:
            retval = os.EX_NOINPUT
    else:
        retval = os.EX_NOINPUT
        
    return retval

def netcraft_submit(options):
    retval = os.EX_OK
    
    url_endpoint = "https://report.netcraft.com/api/v3/report/urls"
        
    malicious_url = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            for line in fd_input:
                line = line.strip()
                if line.startswith(('http://', 'https://')) and validators.url(line):
                    malicious_url.append(line)
                else:
                    if validators.domain(line):
                        malicious_url = malicious_url + ['http://' + line, 'https://' + line]
        
        if malicious_url:
            #pprint.pprint(malicious_url)
            
            # slices of max 1000 url
            for sublist in chunks(malicious_url, 1000):
                req_data = { "email": os.environ['SECRET_NETCRAFT_REPORT_MAIL'],
                             "urls": [] }
                
                for url in sublist:
                    req_data['urls'].append({"country": "FR","reason": "Phishing / scam / malicious URL", "url": url})

                req = requests.post(url_endpoint, json=req_data)
                if req.ok:
                    req_json = req.json()
                    print("[+] Netcraft submit request successful")
                    pprint.pprint(req_json)
                
                else:
                    if req.status_code == 429:
                        print("[!] error while submitting Netcraft URLs : rate limiting, retrying in 60 seconds")
                        pprint.pprint(req.status_code)
                        print(req.content)
                        print(req.headers)
                    
                        time.sleep(60)
                        req = requests.post(url_endpoint, json=req_data)
                        
                    else:
                        print("[!] error while submitting Netcraft URLs")
                        pprint.pprint(req.status_code)
                        print(req.content)
                
                print('-------------------')
        else:
            retval = os.EX_NOINPUT
            
    else:
        retval = os.EX_NOINPUT
        
    return retval

def main():
    global parser
    options = parser.parse_args()
    
    if options.action == 'submit':
        sys.exit(netcraft_submit(options))
    
    elif options.action == 'check':
        sys.exit(netcraft_check(options))

if __name__ == "__main__" :
    main()
