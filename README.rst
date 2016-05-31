SPF2IP
========

This is a Python module which iterates through a domain's SPF record data, and
lists all of the IP addresses found within the SPF record itself, all
"included" SPF records, and IP addresses resolved from the "A/AAAA" records found
in the SPF records and any "MX" records.

This module supports returning both IPv4 and IPv6 addresses.

The output of this module can be used to configure a firewall dynamically when
SMTP traffic should only be received from trusted sources such as in the event
that you want to get email from your cloud provider to your on-premises mail
servers without exposing the SMTP ports to the world.

---

INSTALLATION

Install from pip::

  pip install SPF2IP

---

COMMON USAGE

Command line::

  SPF2IP [-h] --domain DOMAIN [--ip-version {4,6}]

Module::
  
  from SPF2IP import SPF2IP
  lookup = SPF2IP('example.org')

  lookup.IPArray('4')   # Specify the IP version which you would like listed