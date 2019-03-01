import json
import re
import dns.resolver
from ipwhois import IPWhois


def clean(d):
    if type(d) == list:
        return [clean(e) for e in d]
    elif type(d) == dict:
        for k, v in list(d.items()):
            if v is None:
                del d[k]
            else:
                d[k] = clean(v)
    return d


def hasCommands(event):
    if 'type' in event.keys() and event['type'] in ['stdin', 'spyusers']:
        return True
    else:
        return False


def get_domain_ip(domain):
    try:
        result = dns.resolver.query(domain, 'A')
        ip = result[0].to_text()
        return ip
    except:
        return ''


def whois_ip(ip):
    try:
        obj = IPWhois(ip)
        whois_result = obj.lookup_rdap(asn_methods=["whois"])
        return clean(whois_result)
    except:
        return ''


def extractCalloutInfo(event):
    if event['type'] == 'spyusers' and 'args' in event.keys():
        check_string = event['args']
    elif event['type'] == 'stdin':
        check_string = event['fullCommand']
    else:
        return "None"
    
    ip_rgx = "((?:([A-Za-z]{3,9}):\/\/)?([-;:&=\+\$,\w]+@{1})?((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?::(\d+))?((\/[-\+~%\/\.\w]+)?\/?([&?][-\+=&;%@\.\w]+)?(#[\w]+)?)?)"
    domain_rgx = "((?:(?:([A-Za-z]{3,9}):\/\/)|(?:\s)|(?:^){1})([-;:&=\+\$,\w]+@{1})?((?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,10})(?::(\d+))?((\/[-\+~%\/\.\w]+)?\/?([&?][-\+=&;%@\.\w]+)?(#[\w]+)?)?)"

    found_domains = re.findall(domain_rgx, check_string)
    found_ips = re.findall(ip_rgx, check_string)
    
    callouts = []
    for f in set(found_domains):
        callout = {}
        callout['fullUri'] = f[0]
        callout['schema'] = f[1]
        callout['username'] = f[2][0:-1]
        callout['domain'] = f[3]
        callout['port'] = f[4]
        callout['file'] = f[6]
        callout['params'] = f[7]
        if f[3]:
            callout['ip'] = get_domain_ip(f[3])
        if 'ip' in callout.keys() and callout['ip']:
            callout['whoisInfo'] = whois_ip(callout['ip'])
        
        callouts.append(callout)
        

    for f in set(found_ips):
        callout = {}
        callout['fullUri'] = f[0]
        callout['schema'] = f[1]
        callout['username'] = f[2][0:-1]
        callout['ip'] = f[3]
        callout['port'] = f[4]
        callout['file'] = f[6]
        callout['params'] = f[7]
        if 'ip' in callout.keys() and callout['ip']:
            callout['whoisInfo'] = whois_ip(callout['ip'])
        
        callouts.append(callout)

    event['callouts'] = callouts
    return event

async def processEvent(event):

    if not type(event) == dict:
        event = json.loads(event)

    if hasCommands(event):
        event = extractCalloutInfo(event)

    print(event)    
    return event
