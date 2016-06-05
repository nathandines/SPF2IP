import unittest
try:
  #Python3
  from unittest.mock import patch
  from unittest.mock import MagicMock
except ImportError:
  #Python2
  from mock import patch
  from mock import MagicMock
import re
import dns.resolver
import ipaddress

from SPF2IP import SPF2IP
from SPF2IP import dns_request_unicode

# Support testing for unicode in Python2 and Python3
try:
  #Python2
  unicode
except NameError:
  #Python3
  unicode = str

# START - All the stuff required to return fake DNS results
dns_records = {
  'hostrecords.local': {
    'A': ['192.168.0.123','192.168.1.129','256.123.4.198','2a03:2880:f01c:601:dead:beef:0:1'],
    'AAAA': ['192.168.0.123','2a03:2880:f01c:601:DEAD:beef:0:1','2a03:2880:f01c:601:1bad:babe:ffff:ffff'],
    'TXT': [['v=spf1 a aaaa -all']]
  },
  'hostrecords_slash.local': {
    'A': ['192.168.0.123','192.168.1.129','256.123.4.198','2a03:2880:f01c:601:dead:beef:0:1'],
    'AAAA': ['192.168.0.123','2a03:2880:f01c:601:DEAD:beef:0:1','2a03:2880:f01c:601:1bad:babe:ffff:ffff'],
    'TXT': [['v=spf1 a/24 aaaa/96 -all']]
  },
  'hostrecords_external.local': {
    'TXT': [['v=spf1 a:hostrecords.local aaaa:hostrecords.local a: -all']]
  },
  'hostrecords_external_slash.local': {
    'TXT': [['v=spf1 a:hostrecords.local/25 aaaa:hostrecords.local/97 a: -all']]
  },
  'mxrecords.local': {
    'MX': ['mx1.local','mx2.local','mx3.local','noexist.local'],
    'TXT': [['v=spf1 mx -all']]
  },
  'mxrecords_slash.local': {
    'MX': ['mx1.local','mx2.local','mx3.local','noexist.local'],
    'TXT': [['v=spf1 mx/24 -all']]
  },
  'mxrecords_external.local': {
    'TXT': [['v=spf1 mx:mxrecords.local -all']]
  },
  'mxrecords_external_slash.local': {
    'TXT': [['v=spf1 mx:mxrecords.local/25 -all']]
  },
  'mxrecords_external_longslash.local': {
    'TXT': [['v=spf1 mx:mxrecords.local/97 -all']]
  },
  'mx1.local': {
    'A': ['192.168.0.1','192.168.0.5'],
    'AAAA': ['::1','::2']
  },
  'mx2.local': {
    'A': ['192.168.0.129'],
    'AAAA': ['2a03:2880:f01c:601:dead:beef:0:1']
  },
  'mx3.local': {
    'A': ['192.168.2.3'],
    'AAAA': ['2a03:2880:f01c:601:1bad:babe:ffff:ffff']
  },
  'ipv41.local': {
    'TXT': [['v=spf1 ip4:127.0.0.1/32 ip4:127.0.0.1 ip4:127.0.0.5/32 ip4 -all']]
  },
  'ipv42.local': {
    'TXT': [['v=spf1 ip4:127.0.0.1/32 ip4:127.0.0.1/32 ip4:127.0.0.5/32 -all']]
  },
  'ipv43.local': {
    'TXT': [['v=spf1 ip4:127.0.0.2/32 ip4:127.0.0.3/32 ip4:127.0.0.6 ip4:hello -all']]
  },
  'ipv61.local': {
    'TXT': [['v=spf1 ip6:2a03:2880:f01c:601:dead:beef:0:1 ip6:1080::8:800:200C:417A/96 ip6: -all']]
  },
  'ipv62.local': {
    'TXT': [['v=spf1 ip6:2a03:2880:f01c:601:1bad:BABE:0:1 ip6:1080::8:800:200C:417A/96 -all']]
  },
  'ipv63.local': {
    'TXT': [['v=spf1 ip6:::1 ip6:10z0::8:800:200C:417A/96 ip6:hello -all']]
  },
  'redirect.local': {
    'TXT': [['v=spf1 redirect=include.local -all']]
  },
  'noemail.local': {
    'A': ['127.0.0.1'],
    'TXT': [['Dud TXT record']]
  },
  'invalidspf.local': {
    'A': ['127.0.0.1'],
    'TXT': [['v=spf1abc ip4:127.0.0.1/32 ip4:127.0.0.1 ip4:127.0.0.5/32 ip4 -all']]
  },
  'include.local': {
    'TXT': [['v=spf1 include:ipv41.local include:ipv41.local include:ipv42.local include:ipv43.local include:ipv61.local include:ipv62.local include:ipv63.local -all','This is a dud TXT record']]
  },
  'gmail.com': {
    'A': ['127.0.0.1'],
    'AAAA': ['::1'],
    'MX': ['mxrecord.invalid'],
    'TXT': [['v=spf a -all']]
  }
}

class fakedns:
  def __init__(self,value,record_type):
    if record_type == 'TXT':
      self.strings = value
    elif record_type == 'A' or record_type == 'AAAA':
      self.address = value
    elif record_type == 'MX':
      self.exchange = value
def fake_dns_resolver(hostname,record_type):
  try:
    dns_records[hostname]
  except KeyError:
    raise dns.resolver.NXDOMAIN
  else:
    try:
      dns_records[hostname][record_type]
    except KeyError:
      raise dns.resolver.NoAnswer
    else:
      return [fakedns(value,record_type) for value in dns_records[hostname][record_type]]
mock = MagicMock(side_effect=fake_dns_resolver)
# END

class SPF2IPTestCases(unittest.TestCase):
  def test_dns_query_method_output(self):
    # This check here ensures that the output of both the real DNS resolver and the
    # fake DNS resolver (used for the other tests) ends up behaving the same after
    # some slight manipulation
    for record_type in [ 'A', 'AAAA', 'MX', 'TXT' ]:
      # Use a popular third-party email service which isn't likely to go away here
      real_result = dns_request_unicode('gmail.com',record_type)
      with patch('dns.resolver.query',mock) as dns.resolver.query:
        fake_result = dns_request_unicode('gmail.com',record_type)

      for result in [real_result,fake_result]:
        for value in result:
          if record_type == "A":
            self.assertTrue(ipaddress.IPv4Address(value))
          elif record_type == "AAAA":
            self.assertTrue(ipaddress.IPv6Address(value))
          elif record_type == "MX":
            self.assertTrue(isinstance(value,unicode))
          elif record_type == "TXT":
            self.assertTrue(isinstance(value,list))
            for val in value:
              self.assertTrue(isinstance(val,unicode))

  def test_spf_list_is_string_list_with_prefix(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        'v=spf1',
        'include:ipv41.local',
        'include:ipv42.local',
        'include:ipv43.local',
        'include:ipv61.local',
        'include:ipv62.local',
        'include:ipv63.local',
        '-all'
      ]
      lookup = SPF2IP(None)
      output = lookup.GetSPFArray('include.local')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_spf_list_invalid_spf(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = None
      lookup = SPF2IP(None)
      output = lookup.GetSPFArray('invalidspf.local')
      self.assertEqual(output,expected)

  def test_spf_list_without_spf(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = None
      lookup = SPF2IP(None)
      output = lookup.GetSPFArray('noemail.local')
      self.assertEqual(output,expected)

  def test_included_list_is_string_list(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        'ipv41.local',
        'ipv42.local',
        'ipv43.local',
        'ipv61.local',
        'ipv62.local',
        'ipv63.local'
      ]
      lookup = SPF2IP(None)
      output = lookup.FindIncludes('include.local')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_included_without_includes(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = []
      lookup = SPF2IP(None)
      output = lookup.FindIncludes('ipv41.local')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_included_without_spf(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = []
      lookup = SPF2IP(None)
      output = lookup.FindIncludes('noemail.local')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_included_invalid_spf(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = []
      lookup = SPF2IP(None)
      output = lookup.FindIncludes('invalidspf.local')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_single_domain_with_a(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.123/32',
        '192.168.1.129/32'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_a_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.0/24',
        '192.168.1.0/24'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_slash.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_a_external(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.123/32',
        '192.168.1.129/32'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_external.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_a_external_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.0/25',
        '192.168.1.128/25'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_external_slash.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_aaaa(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '2a03:2880:f01c:601:dead:beef:0:1/128',
        '2a03:2880:f01c:601:1bad:babe:ffff:ffff/128'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_aaaa_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '2a03:2880:f01c:601:dead:beef::/96',
        '2a03:2880:f01c:601:1bad:babe::/96'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_slash.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_aaaa_external(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '2a03:2880:f01c:601:dead:beef:0:1/128',
        '2a03:2880:f01c:601:1bad:babe:ffff:ffff/128'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_external.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_aaaa_external_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '2a03:2880:f01c:601:dead:beef::/97',
        '2a03:2880:f01c:601:1bad:babe:8000:0/97'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('hostrecords_external_slash.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_mx_a(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.1/32',
        '192.168.0.5/32',
        '192.168.0.129/32',
        '192.168.2.3/32'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_mx_a_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.0/24',
        '192.168.2.0/24'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_slash.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_mx_a_external(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.1/32',
        '192.168.0.5/32',
        '192.168.0.129/32',
        '192.168.2.3/32'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_external.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_mx_a_external_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '192.168.0.0/25',
        '192.168.0.128/25',
        '192.168.2.0/25'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_external_slash.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_mx_a_external_longslash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = []
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_external_longslash.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_with_mx_aaaa(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '::1/128',
        '::2/128',
        '2a03:2880:f01c:601:dead:beef:0:1/128',
        '2a03:2880:f01c:601:1bad:babe:ffff:ffff/128'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_mx_aaaa_slash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '::/24',
        '2a03:2800::/24'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_slash.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_mx_aaaa_external(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '::1/128',
        '::2/128',
        '2a03:2880:f01c:601:dead:beef:0:1/128',
        '2a03:2880:f01c:601:1bad:babe:ffff:ffff/128'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_external.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_with_mx_aaaa_external_longslash(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '::/97',
        '2a03:2880:f01c:601:dead:beef::/97',
        '2a03:2880:f01c:601:1bad:babe:8000:0/97'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('mxrecords_external_longslash.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_ip4(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '127.0.0.1/32',
        '127.0.0.5/32'
      ]
      lookup = SPF2IP(None)
      output = lookup.Worker('ipv41.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_single_domain_ip6(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      lookup = SPF2IP(None)
      expected = [
        '127.0.0.1/32',
        '127.0.0.5/32'
      ]
      output = lookup.Worker('ip61.local','6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertNotEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_single_domain_empty(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = []
      lookup = SPF2IP(None)
      output = lookup.Worker('noemail.local','4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_ip4_results(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '127.0.0.1/32',
        '127.0.0.2/32',
        '127.0.0.3/32',
        '127.0.0.5/32',
        '127.0.0.6/32'
      ]
      lookup = SPF2IP('redirect.local')
      output = lookup.IPArray('4')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv4Network(entry))

  def test_ip6_results(self):
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      expected = [
        '1080::8:800:0:0/96',
        '2a03:2880:f01c:601:dead:beef:0:1/128',
        '2a03:2880:f01c:601:1bad:babe:0:1/128',
        '::1/128'
      ]
      lookup = SPF2IP('redirect.local')
      output = lookup.IPArray('6')
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))
      for entry in output:
        self.assertTrue(isinstance(entry,unicode))
        self.assertTrue(ipaddress.IPv6Network(entry))

  def test_domain_without_spf_results(self):
    expected = []
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      lookup = SPF2IP('noemail.local')
      output = lookup.IPArray()
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

  def test_nonexistent_domain_results(self):
    expected = []
    with patch('dns.resolver.query',mock) as dns.resolver.query:
      lookup = SPF2IP('noexist.local')
      output = lookup.IPArray()
      self.assertTrue(type(output) is list)
      self.assertEqual(sorted(list(set(output))),sorted(output))
      self.assertEqual(output,sorted([entry.lower() for entry in expected]))

if __name__ == '__main__':
  unittest.main()
