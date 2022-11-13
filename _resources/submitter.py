#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import argparse
import requests

import code
import pprint

# Script version
VERSION = '1.0'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
parser.add_argument('-i', '--input-file', help='Input file (either list of newline-separated FQDN, or a list newline-separated of CRDF refs)')
parser.add_argument('-a', '--action', help = 'Action to do on CRDF (default \'submit\')', choices = ['submit', 'check'], type=str.lower, default = 'submit')

def crdf_check(options):
    retval = os.EX_OK
    
    url_endpoint = "https://threatcenter.crdf.fr/api/v0/submit_get_info.json"
    refs = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            refs = fd_input.read().splitlines()
        
        if refs:
            #pprint.pprint(refs)
            
            for ref in refs:
                req_data = {"token": os.environ['SECRET_CRDF_API_KEY'], "ref": ref}
                req = requests.post(url_endpoint, json=req_data)
                print("[+] CRDF ref '%s'" % ref)
                
                if req.ok:
                    req_json = req.json()
                    if req_json.get('error') == False:
                        print("[+] CRDF check request successful")
                        pprint.pprint(req_json)
                else:
                    print("[!] error while checking CRDF ref")
                    pprint.pprint(req.status_code)
                    retval = os.EX_DATAERR
                
                print('-------------------')
                
            else:
                retval = os.EX_NOINPUT
    else:
        retval = os.EX_NOINPUT
        
    return retval

def crdf_submit(options):
    retval = os.EX_OK
    
    url_endpoint = "https://threatcenter.crdf.fr/api/v0/submit_url.json"
    malicious_url = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            data = fd_input.read().splitlines()
            malicious_url = list(map(lambda fqdn: "http://" + fqdn, data)) + list(map(lambda fqdn: "https://" + fqdn, data))
        
        if malicious_url:
            #pprint.pprint(malicious_url)
            
            req_data = {"token": os.environ['SECRET_CRDF_API_KEY'], "urls": malicious_url}
            req = requests.post(url_endpoint, json=req_data)
            
            if req.ok:
                req_json = req.json()
                if req_json.get('error') == False:
                    print("[+] CRDF submit request successful")
                    pprint.pprint(req_json)
            else:
                print("[!] error while submitting CRDF URLs")
                pprint.pprint(req.status_code)
                retval = os.EX_DATAERR
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
        sys.exit(crdf_submit(options))
    
    elif options.action == 'check':
        sys.exit(crdf_check(options))

if __name__ == "__main__" :
    main()