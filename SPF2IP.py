import dns.resolver
import re
import argparse
import ipaddress

# Support unicode parameter in Python2 and Python3
try:
  #Python2
  unicode
except NameError:
  #Python3
  unicode = str

def dns_request_unicode(hostname,record_type,*args,**kwargs):
  output = []
  try:
    result = dns.resolver.query(hostname,record_type,*args,**kwargs)
  except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):
    return output
  for entry in result:
    if record_type == "A":
      value = entry.address
      if type(value) is not unicode:
        value = value.decode('utf-8')
      output.append(value)
    elif record_type == "AAAA":
      value = entry.address
      if type(value) is not unicode:
        value = value.decode('utf-8')
      output.append(value)
    elif record_type == "MX":
      value = entry.exchange
      if type(value) is not unicode:
        value = value.__str__().encode('utf-8').decode('utf-8')
      output.append(value)
    elif record_type == "TXT":
      value = entry.strings
      suboutput = []
      for val in value:
        if type(val) is not unicode:
          val = val.decode('utf-8')
        suboutput.append(val)
      output.append(suboutput)
  return output

ip_sorter = {
  '4': lambda addr: int(ipaddress.IPv4Address(addr.split('/')[0])),
  '6': lambda addr: int(ipaddress.IPv6Address(addr.split('/')[0]))
}

class SPF2IP:
  def __init__(self, domain):
    self.included_domains = [ domain ]

  def IPArray(self,ip_version='4'):
    ips = []
    CheckedDomains = []

    while True:
      remaining = set(self.included_domains) - set(CheckedDomains)
      if not remaining:
        break
      for domain in self.included_domains:
        if domain not in CheckedDomains:
          NewIncludes = self.FindIncludes(domain)
          for entry in NewIncludes:
            self.included_domains.append(entry)
          CheckedDomains.append(domain)

    for domain in self.included_domains:
      data = self.Worker(domain,ip_version)
      for entry in data:
        ips.append(entry)
    return sorted(list(set(ips)),key=ip_sorter[ip_version])

  def FindIncludes(self,domain):
    includes = []

    entries = self.GetSPFArray(domain)

    for entry in entries:
      regex = re.match(r'^\+?(?:include:|(?:exp|redirect)=)(?P<value>.*)',entry)
      if regex:
        if regex.group('value') not in self.included_domains:
          includes.append(regex.group('value'))
    return sorted(list(set(includes)))

  def GetSPFArray(self, domain):
    results = dns_request_unicode(domain,'TXT')
    for rrset in results:
      for txtrecord in rrset:
        if re.match(r'v=spf1 ',txtrecord):
          return sorted(list(set(txtrecord.lower().split())))
    # Default return
    return []

  def Worker(self,domain,ip_version):
    output = []

    ip_types = {
      '4': {
        'dns_hostname_type': 'A',
        'spf_ip_prefix': 'ip4',
        'ipaddress_class': ipaddress.IPv4Network 
      },
      '6': {
        'dns_hostname_type': 'AAAA',
        'spf_ip_prefix': 'ip6',
        'ipaddress_class': ipaddress.IPv6Network
      }
    }

    entries = self.GetSPFArray(domain)

    for entry in entries:
      regex = re.match(r'^\+?(?P<type>[^:/]+)(?::(?P<address>[^/]+))?(?P<mask>/[0-9]+)?',entry)
      values = []
      if regex:
        if regex.group('type') == ip_types[ip_version]['spf_ip_prefix']:
          if regex.group('mask'):
            values.append(regex.group('address')+regex.group('mask'))
          else:
            values.append(regex.group('address'))
        elif regex.group('type').upper() == ip_types[ip_version]['dns_hostname_type']:
          if regex.group('address'):
            address_results = dns_request_unicode(regex.group('address'),ip_types[ip_version]['dns_hostname_type'])
          else:
            address_results = dns_request_unicode(domain,ip_types[ip_version]['dns_hostname_type'])
          for address in address_results:
            if regex.group('mask'):
              values.append(address+regex.group('mask'))
            else:
              values.append(address)
        elif regex.group('type').upper() == 'MX':
          if regex.group('address'):
            mx_results = dns_request_unicode(regex.group('address'),'MX')
          else:
            mx_results = dns_request_unicode(domain,'MX')
          for exchange in mx_results:
            address_results = dns_request_unicode(exchange,ip_types[ip_version]['dns_hostname_type'])
            for address in address_results:
              if regex.group('mask'):
                values.append(address+regex.group('mask'))
              else:
                values.append(address)
      for value in values:
        try:
          result = ip_types[ip_version]['ipaddress_class'](value,strict=False)
        except (ipaddress.AddressValueError,ipaddress.NetmaskValueError):
          pass
        else:
          output.append(result.compressed.lower())

    return sorted(list(set(output)),key=ip_sorter[ip_version])

def main():
  parser = argparse.ArgumentParser(description="Script to extract IP addresses from a SPF record into a list")
  parser.add_argument('--domain',required=True,help='Domain for which the IP addresses should be extracted')
  parser.add_argument('--ip-version',choices=['4','6'],default='4',help='Define version of IP list to extract')

  args = parser.parse_args()

  lookup = SPF2IP(args.domain)
  if lookup:
    for ip in lookup.IPArray(args.ip_version):
      print(ip)

if __name__ == "__main__":
    main()
