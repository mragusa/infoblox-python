#!/usr/bin/env python3

import dns.resolver

def resolve_a(hostname, nameserver):
    qname = dns.name.from_text(hostname)
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.query.udp(q, nameserver )
    a_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.A)
    if a_rrset:
        for arr in a_rrset:
            return(arr.to_text())

def query_ns (domain, nameserver):
    qname = dns.name.from_text(domain)
    q = dns.message.make_query(qname, dns.rdatatype.NS)
    #   print("The query is:")
    #print(q)
    #print("")
    r = dns.query.udp(q, nameserver )
    #print("The response is:")
    #print(r)
    #print("")
    #print("The nameservers are:")
    ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
    if ns_rrset:
        ns_results = {} 
        for rr in ns_rrset:
            ns_ip_address = resolve_a(rr.target.to_text(), nameserver)
            if ns_ip_address:
                ns_results[rr.target.to_text()] = ns_ip_address
        return(ns_results)

def main ():
    domain = 'google.com'
    nameserver = '8.8.8.8'
    print("Querying for {}".format(domain))
    domain_ns = query_ns(domain, nameserver)    
    glue_ns = {}
    print("Querying {} name servers".format(domain))
    print(domain_ns)
    for dns in domain_ns:
        glue_ns_results = query_ns(domain, domain_ns[dns])
        glue_ns[dns] = glue_ns_results
        #print(glue_ns)
        if domain_ns == glue_ns[dns]:
            print("{} Glue Matches against {}".format(domain, dns))
            print(glue_ns[dns])
        else:
            print("{} Glue Failed against {}".format(domain, dns))
            print(glue_ns[dns])

if __name__ == "__main__":
    main()
