#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import socket
import cymruwhois
import requests
import functools
import concurrent.futures
import csv
import time
import datetime

import code
import pprint

from os import path
from lxml.html.soupparser import fromstring as fromstringhtml
from lxml.etree import fromstring as fromstringxml

# Script version
VERSION = '1.2'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
input_group = parser.add_mutually_exclusive_group()
input_group.add_argument('-i', '--input-url', help='Input a single red.flag.domains URL', default = None)
input_group.add_argument('-d', '--date', help='Get a specific date of red.flag.domains publication', choices = ['today', 'yesterday'], default = None)
input_group.add_argument('-a', '--all', help='Get all red.flag.domains publications ever', default = False, action='store_true')
input_group.add_argument('-f', '--input-file', help='Input file as a list of newline-separated red.flag.domains URL', default = None)
input_group.add_argument('-r', '--refresh', help='Take an existing CSV output file and refresh records', default = None)
parser.add_argument('-o', '--output-dir', help='Output directory (default: current working directory)', default = os.getcwd())

def enrich(entry):
    #print("[+] %s" % entry)
    cymru_resolver = cymruwhois.Client()
    
    current = {}
    current['fqdn'] = entry
    try:
        current['ip'] = socket.gethostbyname(entry)
        
        try:
            current['info'] = vars(cymru_resolver.lookup(current['ip']))
        except:
            print("[!] can't resolve info from cymru for '%s'" % entry)
        
    except:
        current['ip'] = ''
        current['info'] = ''
        pass
    
    finally:
        cymru_resolver.disconnect()
        return current

def generate_csv(year, month, day, results, outdir, link):
    keys = ['fqdn', 'ip', 'asn', 'ip_prefix', 'owner', 'cc']
    if results:
        output_month_dir = os.path.abspath(os.path.join(outdir, year, month))
        
        if not os.path.exists(output_month_dir):
            os.makedirs(output_month_dir)
            
        output_day_file = os.path.join(output_month_dir, "%s-%s-%s.csv" % (year, month, day))
        with open(output_day_file, mode='w', encoding='utf-8') as fd_output:
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
        
        print("[+] %s entries of '%s' written to output file '%s'" % (len(results), link, output_day_file))
    
    return

def scrape(url, output_dir):
    p_date = re.compile(r'(?P<year>[\d]{4})-(?P<month>[\d]{2})-(?P<day>[\d]{2})')
    
    print("[+] URL '%s'" % url)
    
    result = {}
    
    req = requests.get(url)
    
    data_scraped = fromstringhtml(req.content).xpath('/html/body/div/article/div/p')
    #code.interact(local=locals())
    
    if data_scraped:
        data = []
        
        for p_paragraph in data_scraped:
            items = p_paragraph.text_content().splitlines()
            
            for item in items:
                item = item.replace('[','').replace(']','')
                data.append(re.search(r'^(?P<fqdn>[^\s]*)[\s]?', item).group('fqdn'))
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (target, executor.submit(functools.partial(enrich, target)))
                for target in data ]
        
        for entry, entry_enriched in futs:
            if entry not in result.keys():
                result[entry] = entry_enriched.result()
        
        if result:
            p_date_search = p_date.search(url)
            if p_date_search:
                year, month, day = p_date_search.group('year'), p_date_search.group('month'), p_date_search.group('day')
                generate_csv(year, month, day, result, output_dir, url)
            else:
                print("[!] can't find data for post '%s'" % url)
    
    else:
        print("[!] can't find data for post '%s' | status code '%s'" % (url, req.status_code))
        
    return result


def main():
    global parser
    options = parser.parse_args()
    
    links_data = []
    
    if options.date:
        now = datetime.date.today()
        
        if options.date == 'yesterday':
            now = now - datetime.timedelta(days=1)
        
        url = "%s%s/" % ("https://red.flag.domains/posts/", now.strftime('%Y-%m-%d'))
        links_data.append(url)
    
    elif options.input_url:
        links_data = [options.input_url]
        
    elif options.input_file:
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            links_data = fd_input.read().splitlines()
    
    elif options.all:
        rss_url = 'https://red.flag.domains/index.xml'
        links_data = fromstringxml(requests.get(rss_url).content).xpath('//item/guid[contains(text(),"posts")]/text()')
    
    if links_data:
        print("[+] %s post(s)\n" % len(links_data))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = [ (link, executor.submit(functools.partial(scrape, link, options.output_dir)))
                    for link in links_data ]
    
    return
    
if __name__ == "__main__" :
    main()