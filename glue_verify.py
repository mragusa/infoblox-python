#!/usr/bin/env python3

import dns.resolver
import argparse

def resolve_a(hostname, nameserver):
    qname = dns.name.from_text(hostname)
    print("Querying {} for {}".format(nameserver, hostname))
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.query.udp(q, nameserver,timeout=2)
    try:
        a_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.A)
    except Exception as e:
        print("Error: {}".format(e))
    if a_rrset:
        print("A_RRSet", a_rrset)
        for arr in a_rrset:
            return(arr.to_text())
    #except (dns.exception.DNSException,dns.rcode.UnknownRcode,dns.exception.Timeout) as e:
    #    print(e)

def query_ns (domain, nameserver):
    qname = dns.name.from_text(domain)
    q = dns.message.make_query(qname, dns.rdatatype.NS)
    r = dns.query.udp(q, nameserver )
    ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
    if ns_rrset:
        print("NS Query", ns_rrset)
        ns_results = {} 
        for rr in ns_rrset:
            ns_ip_address = resolve_a(rr.target.to_text(), nameserver)
            if ns_ip_address:
                ns_results[rr.target.to_text()] = ns_ip_address
        return(ns_results)

def main ():
    parser = argparse.ArgumentParser(description='Verify glue records for domains',)
    parser.add_argument("-d", "--domain", help="Domain to verify")
    parser.add_argument("-n", "--nameserver", help="Name server to begin tree")
    args = parser.parse_args()
    domain = args.domain
    nameserver = args.nameserver
    print("Querying for {}".format(domain))
    domain_ns = query_ns(domain, nameserver)    
    glue_ns = {}
    print("Querying {} name servers".format(domain))
    print(domain_ns)
    for dns in domain_ns:
        glue_ns_results = query_ns(domain, domain_ns[dns])
        glue_ns[dns] = glue_ns_results
        print("Glue", glue_ns)
        if domain_ns == glue_ns[dns]:
            print("{} Glue Matches against {}".format(domain, dns))
            print(glue_ns[dns])
        else:
            print("{} Glue Failed against {}".format(domain, dns))
            print(glue_ns[dns])

if __name__ == "__main__":
    main()
