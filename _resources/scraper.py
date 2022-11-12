#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import socket
import cymruwhois
import requests
import functools
import types
import concurrent.futures
import csv
import time
import datetime

import code
import pprint

from os import path
from lxml.html.soupparser import fromstring

# Script version
VERSION = '1.0'

def enrich(entry):
    print("[+] %s" % entry)
    cymru_resolver = cymruwhois.Client()
    
    current = {}
    current['fqdn'] = entry
    try:
        current['ip'] = socket.gethostbyname(entry)
        current['info'] = vars(cymru_resolver.lookup(current['ip']))
    except:
        current['ip'] = ''
        current['info'] = ''
        pass
    
    finally:
        return current

def scrape(now):
    result = {}
    
    url = "%s%s/" % ("https://red.flag.domains/posts/", now.strftime('%Y-%m-%d'))
    print("[+] URL '%s'" % url)
    data_scraped = fromstring(requests.get(url).content).xpath('/html/body/div/article/div/p')
    
    if data_scraped:
        data = []
        
        for p_paragraph in data_scraped:
            data = data + p_paragraph.text_content().replace('[','').replace(']','').splitlines()
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (target, executor.submit(functools.partial(enrich, target)))
                for target in data ]
        
        for entry, entry_enriched in futs:
            if entry not in result.keys():
                result[entry] = entry_enriched.result()
        
    return result

def generate_csv(results, now):
    keys = ['fqdn', 'ip', 'asn', 'ip_prefix', 'owner', 'cc']
    if results:
        with open('./%s/%s/%s.csv' % (now.strftime('%Y'), now.strftime('%m'), now.strftime('%Y-%m-%d')), mode='w', encoding='utf-8') as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=',', quoting=csv.QUOTE_ALL, lineterminator='\n')
            spamwriter.writerow(keys)
            
            for entry,entry_enriched in sorted(results.items()):
                output_line = []
                
                if not(entry_enriched['info']):
                    entry_ip = ''
                    entry_asn = ''
                    entry_ip_prefix = ''
                    entry_owner = ''
                    entry_cc = ''
                
                else:
                    entry_ip = entry_enriched['info']['ip']
                    entry_asn = entry_enriched['info']['asn']
                    entry_ip_prefix = entry_enriched['info']['prefix']
                    entry_owner = entry_enriched['info']['owner']
                    entry_cc = entry_enriched['info']['cc']
                
                output_line = [entry_enriched['fqdn'], entry_ip, entry_asn, entry_ip_prefix, entry_owner, entry_cc]
                spamwriter.writerow(output_line) 
                
        print("[+] %s entries written to output file" % len(results))
    
    return

# execution is next day, grabbing previous day results
now = datetime.date.today() - datetime.timedelta(days=1)

#yesterday = now - datetime.timedelta(days=1)

results = scrape(now)
generate_csv(results, now)
