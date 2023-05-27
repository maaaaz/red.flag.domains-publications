#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import requests
import time

import code
import pprint

from w3lib.url import safe_url_string
import validators

# Script version
VERSION = '1.0'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
parser.add_argument('-i', '--input-file', help='Input file (either list of newline-separated FQDN or URL (for reporting) || submission UUID (for checking reports)')
parser.add_argument('-a', '--action', help = 'Action to do on Netcraft (default \'submit\')', choices = ['submit', 'check'], type=str.lower, default = 'submit')

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def netcraft_check(options):
    retval = os.EX_OK
    
    url_endpoint = "https://report.netcraft.com/api/v3/submission/"
    refs = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            refs = fd_input.read().splitlines()
        
        if refs:
            #pprint.pprint(refs)
            
            for ref in refs:
                req = requests.get(url_endpoint + ref)
                print("[+] Netcraft ref '%s'" % ref)
                
                if req.ok:
                    req_json = req.json()
                    print("[+] Netcraft check request successful")
                    pprint.pprint(req_json)
                
                else:
                    print("[!] error while checking Netcraft ref")
                    pprint.pprint(req.status_code)
                    print(req.content)
                
                print('-------------------')
                
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
    
    if options.input_file == None:
         parser.error('Please specify a valid input file or a valid URL')
    
    if options.action == 'submit':
        sys.exit(netcraft_submit(options))
    
    elif options.action == 'check':
        sys.exit(netcraft_check(options))

if __name__ == "__main__" :
    main()
