import argparse
import netifaces
import dns.resolver
import datetime
import socket
import requests
import importlib.metadata
from scapy.all import *
from pythonping import ping
from colorama import Fore, Style

VERSION = importlib.metadata.version('netcheckdbg')
DEFAULT_TEST_NAMES = [
  'google.com',
  'cloudflare.com',
  'wikipedia.org'
]

def main() -> None:
  """
  Entry point of the program. Handles command line arguments
  and executes the different checks.
  """
  # Parse arguments
  parser = argparse.ArgumentParser(
    prog=f'netcheckdbg {VERSION}',
    description='netcheckdbg is a tool for checking and debugging netowrk connectivity. It checks for possible points of failure that may lead to connectivity issues. It can also generate route traces and then test each hop as part of network testing.'
  )
  parser.add_argument(
    '-r',
    '--test-remote',
    help='Test connection to specific remote host',
    type=str
  )
  parser.add_argument(
    '-n',
    '--no-default',
    help='Do not use default test hosts',
    action='store_true'
  )
  parser.add_argument(
    '-t',
    '--trace-file',
    help='Test a specific traced route to a remote host using a trace file',
    type=str
  )
  parser.add_argument(
    '-g',
    '--gen-trace',
    help='Generate a new trace file for a given remote host, skips network checks',
    type=str
  )

  args = parser.parse_args()

  if args.gen_trace:
    trace_route(socket.gethostbyname(args.gen_trace))
    return

  test_names = DEFAULT_TEST_NAMES if not args.no_default else []
  if args.test_remote != None:
    test_names.append(args.test_remote)

  print(f'--- netcheckdbg ---')
  print(f'v {VERSION}')
  print(datetime.now())
  print(socket.gethostname())
  print('---\n')

  # Run checks
  print(f'╭ Checking {Style.BRIGHT}interfaces{Style.RESET_ALL}')
  (success_ifaces, ifaces) = check_interfaces()
  if success_ifaces:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Interface check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}gateway configuration{Style.RESET_ALL}')
  # Save gateways for later
  (success_gateways, gateways) = check_gateway_conf(ifaces)
  if success_gateways:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Gateway check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}DNS configuration{Style.RESET_ALL}')
  # Save nameservers for later
  (success_dns_conf, nameservers) = check_dns_conf()
  if success_dns_conf:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ DNS configuartion check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}gateway reachability{Style.RESET_ALL}')
  success_gateway_reach = check_reach_gateways(gateways)
  if success_gateway_reach:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Gateway reachability check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}name server reachability{Style.RESET_ALL}')
  success_dns_reach = check_reach_dns(nameservers)
  if success_dns_reach:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Name server reachability check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}DNS name resolution{Style.RESET_ALL}')
  success_dns_resolve = check_dns_resolution(test_names)
  if success_dns_resolve:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Name resolution check has failed!{Fore.RESET}')

  print(f'╭ Checking {Style.BRIGHT}internet reachability{Style.RESET_ALL}')
  success_inet_reach = check_inet_reach(test_names)
  if success_inet_reach:
    print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
  else:
    print(f'╰{Fore.RED} ❌ Internet reachability check has failed!{Fore.RESET}')

  # Run trace checks
  if args.trace_file:
    print(f'╭ Checking {Style.BRIGHT}route trace file {args.trace_file}{Style.RESET_ALL}')
    success_trace = check_trace(args.trace_file)
    if success_trace:
      print(f'╰{Fore.GREEN} ✓ Success{Fore.RESET}')
    else:
      print(f'╰{Fore.RED} ❌ Route trace check has failed!{Fore.RESET}')

def check_interfaces() -> tuple[bool, list[str]]:
  """
  This function checks for available network interfaces
  """
  success = False
  ifaces = netifaces.interfaces()
  # List interfaces
  for iface in ifaces:
    print(f'├ Found interface {iface}:')
    # Get IPv4/IPv6 addresses
    addrs = netifaces.ifaddresses(iface)
    ip_addrs = addrs[netifaces.AF_INET] if netifaces.AF_INET in addrs else {}
    ip_addrs = ip_addrs + addrs[netifaces.AF_INET6] if netifaces.AF_INET6 in addrs else ip_addrs

    # List addresses
    if len(ip_addrs) < 1:
      print(f'│   {Fore.YELLOW}No IPv4/IPv6 addresses found!{Fore.RESET}')
    else:
      for address in ip_addrs:
        success = True
        print(f'│   Address {address["addr"]}/{address["netmask"]}')
  return (success, ifaces)

def check_gateway_conf(interfaces: list[str]) -> tuple[bool, list[str]]:
  """
  Checks that interfaces have configured gateways
  """
  # Get gateways
  data = netifaces.gateways()
  all_gateways = data[netifaces.AF_INET] if netifaces.AF_INET in data else []
  all_gateways = all_gateways + data[netifaces.AF_INET6] if netifaces.AF_INET6 in data else all_gateways
  all_gateways.sort(key=lambda t: t[1])
  success = False

  # List gateways
  for gateway_addr, iface, default in all_gateways:
    if iface in interfaces:
      print(f'├ For interface {iface}:')
      print(f'│   {gateway_addr} {"(Default)" if default else None}')
      success = True
  
  # Return success and list of gateways
  return (success, [t[0] for t in all_gateways])

def check_dns_conf() -> tuple[bool, list[str]]:
  """
  Checks that DNS servers are configured
  """
  dns_resolver = dns.resolver.Resolver()
  for ns in dns_resolver.nameservers:
    print(f'├ Found name server {ns}')

  # Return success and list of nameservers
  return (len(dns_resolver.nameservers) > 0, dns_resolver.nameservers)

def check_reach_gateways(gateways: list[str]) -> bool:
  """
  Checks that gateways are reachable with ICMP and TCP/HTTP
  """
  success = False
  for g in gateways:
    # ICMP
    print(f'├ Testing gateway {g} with ICMP')
    err = check_reach_icmp(g)
    if not err:
      print('│   Reachable')
      success = True
    else:
      print(f'│   {Fore.YELLOW}Could not reach gateway with error: {err}{Fore.RESET}')

    # TCP
    print(f'├ Testing gateway {g} port 80 with TCP')
    (err, local_addr) = check_reach_tcp(g, 80)
    print(f'│   Socket has local address {local_addr}')
    if not err:
      print('│   Reachable')
      success = True
    else:
      print(f'│   {Fore.YELLOW}Could not reach gateway with error: {err}{Fore.RESET}')

    # HTTP
    print(f'├ Testing gateway {g} with HTTP')
    err = check_reach_http(f'http://{g}')
    if not err:
      print('│   Reachable')
      success = True
    else:
      print(f'│   {Fore.YELLOW}Could not reach gateway with error: {err}{Fore.RESET}')
  return success

def check_reach_dns(nameservers: list[str]) -> bool:
  """
  Checks that DNS servers are reachable with ICMP
  """
  success = False
  for ns in nameservers:
    print(f'├ Testing name server {ns} with ICMP')
    err = check_reach_icmp(ns)
    if not err:
      print('│   Reachable')
      success = True
    else:
      print(f'│   {Fore.YELLOW}Could not reach name server with error: {err}{Fore.RESET}')
  return success

def check_reach_icmp(dest: str) -> str|None:
  """
  Checks if a host is reachable with ICMP. Returns error if not, None otherwise
  """
  try:
    p = ping(dest, count=1)
    if p.stats_packets_returned >= p.stats_packets_sent:
      return None
    else:
      return 'Packets dropped'
  except Exception as err:
    return err
  
def check_reach_tcp(dest: str, port: int) -> tuple[str|None, str]:
  """
  Checks if a host is reachable with TCP. Retruns tuple (error|None, socket local address)
  """
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect((dest, port))
      local_addr = s.getsockname()
      return (None, f'{local_addr[0]}:{local_addr[1]}')
  except Exception as err:
    return (err, '')

def check_reach_http(dest: str) -> str|None:
  """
  Checks if a host is reachable with HTTP. Returns error if not, None otherwise
  """
  try:
    requests.get(dest)
    return None
  except Exception as err:
    return err

def check_dns_resolution(names: list[str]) -> bool:
  """
  Checks that a list of names are resolved with DNS
  """
  success = False
  for name in names:
    print(f'├ Testing name resolution for {name}')
    try:
      ip = socket.gethostbyname(name)
      print(f'│   Resolved with host {ip}')
      success = True
    except Exception as err:
      print(f'│   {Fore.YELLOW}No host found!{Fore.RESET}')
  return success

def check_inet_reach(hosts: list[str]) -> bool:
  """
  Checks if a list of hosts are reachable with ICMP, TCP and HTTP
  """
  try:
    success = False
    for host in hosts:
      print(f'├ Testing {host} reachability')
      err = check_reach_icmp(socket.gethostbyname(host))
      if err:
        print(f'│   {Fore.YELLOW}ICMP failed with error: {err}{Fore.RESET}')
      else:
        print('│   ICMP reachable')
        success = True

      (err, local_addr) = check_reach_tcp(socket.gethostbyname(host), 80)
      print('│   Testing TCP')
      print(f'│     Socket has local address {local_addr}')
      if err:
        print(f'│     {Fore.YELLOW}TCP port 80 failed with error: {err}{Fore.RESET}')
      else:
        print('│     TCP port 80 reachable')
        success = True

      err = check_reach_http(f'http://{host}')
      if err:
        print(f'│   {Fore.YELLOW}HTTP failed with error: {err}{Fore.RESET}')
      else:
        print('│   HTTP reachable')
        success = True

    return success
  except Exception as err:
    return False

def check_trace(trace_file: str) -> bool:
  """
  Checks that a list of hosts from a trace file are reachable
  """
  success = False
  with open(trace_file, 'r') as file:
    hosts = file.readlines()
    hosts = [h.strip() for h in hosts]
    print(f'├ Testing traced route to {hosts[-1]}')
    for host in hosts:
      err = check_reach_icmp(host)
      if err:
        print(f'│   {Fore.YELLOW}Failed to reach {host} with ICMP: {err}{Fore.RESET}')
      else:
        print(f'│   Reached {host} with ICMP')
        if host == hosts[-1]:
          success = True
  return success

def trace_route(destination, max_hops=15, timeout=2) -> None:
  """
  Generates a traceroute
  """
  # Start by getting the local address to set in the trace packets
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(('1.1.1.1', 80))
    local_addr = s.getsockname()[0]
    for ttl in range(1, max_hops + 1):
      pkt = IP(dst=destination, ttl=ttl, src=local_addr) / ICMP()
      reply = sr1(pkt, verbose=0, timeout=timeout)
      
      if reply != None:
        print(reply.src)
        if reply.type == 0:
          break
  print(destination)

if __name__ == '__main__':
  main()