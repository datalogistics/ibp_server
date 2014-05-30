#!/usr/bin/env python
"""
Name: Ibp_server configuration script
Description: Helps in auto configuration of ibp_server.
"""
import socket
import fcntl
import struct
import sys
import os
import commands
import os.path as path
import time
import array
import shutil
import argparse
import ConfigParser
import logging

# Setting basic logging
log = logging.getLogger('ibp_configure')
log.setLevel(logging.DEBUG)

# Configurable parameters starts
IBP_PORT=6714
ALLOCATION_SIZE = 8000  #mb
UNIS_ENDPOINT = "http://localhost:8888"
# if SSL_UNIS_* is set then unis is assumed to talk over ssl
UNIS_SSL_ENABLED = False
UNIS_SSL_KEY = "/root/ssl/client.key"
UNIS_SSL_CERT = "/root/ssl/client.crt"
LOGFILENAME = "ibp_configure.log"
WAIT_INTERVAL = 10 #seconds to wait before interfaces are up

# location constants
IBP_RESOURCE_ROOT = "/tmp/ibp_resources"
IBP_ROOT      = "/"

class Configuration():

    def __init__(self, ibp_root=IBP_ROOT, resource_root=IBP_RESOURCE_ROOT, size=ALLOCATION_SIZE):
        self.ibp_root = ibp_root
        self.resource_root = resource_root
        self.size = size

    def allocation_success_file(self):
        # acts as lock for reallocation. This file will be created when resources are
        # allocated for ibp_server. If this file is removed then resources will be
        # reallocated (and all original data will be lost)
        return os.path.join(self.resource_root, ".allocations_do_not_remove")

    def resource_base_dir(self):
        return self.resource_root

    def resource_db(self):
        return path.join(self.resource_root, "db")

    def makefs_cmd(self):
        return path.join(self.ibp_root, "bin/mkfs.resource") + " 0 dir " + self.resource_base_dir()\
               + " " + self.resource_db() + " " + str(self.size)

    def ibp_config_path(self):
        return path.join(self.ibp_root, "etc/ibp.cfg")

    def ibp_interface_monitor(self):
        return path.join(self.ibp_root, "bin/ibp_interface_monitor.py") + " -l -d"

IBP_SAMPLE_CONFIG = """
# Do not modify this directly. It will loose change after service restart.
# Change in ibp_configure.py and then do 'service ibp-server restart'

[server]
interfaces={interfaces}
lazy_allocate=1
threads=16
log_file=/var/log/ibp_server.log
password=ibp
big_alloc_enable=1
substitute_map={substitute_map}

[phoebus]
{phoebus}

{resource}

[unis]
{unis}

"""

PHOEBUS_SAMPLE_CONFIG = "gateway={phoebus_gateway}"

UNIS_SAMPLE_CONFIG = """name = IBP Server
type = ibp_server
endpoint = {unis_endpoint}
protocol_name= ibp
registration_interval = 120
publicip = {public_ip}
publicport = 6714
use_ssl = {use_ssl}
client_certfile={cert_file_path}
client_keyfile={key_file_path}
"""

c = Configuration()

def query_yes_no(question, default="no"):
    """Ask a yes/no question via raw_input() and return their answer.
    
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

def execute_command(cmd, ignore_status = False):
  log.debug("Command to run: %s" % cmd)
  (status, output) = commands.getstatusoutput(cmd)
  if status and not ignore_status:    ## Error case, print the command's output to stderr and exit
    log.error(output)
    sys.exit(1)
  return output

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(),
      0x8915,  # SIOCGIFADDR
      struct.pack('256s', ifname[:15])
      )[20:24])

def all_interfaces():
    is_64bits = sys.maxsize > 2**32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8 # initial value                                                                                                                                                                         
    while True:
        bytes = max_possible * struct_size
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF                                                                                                                                                                           
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        if outbytes == bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, struct_size):
        name = namestr[i:i+16].split('\0', 1)[0]
        ip   = namestr[i+20:i+24]
        lst.append((name, ip))
    return lst

def format_ip(addr):
    return str(ord(addr[0])) + '.' + \
           str(ord(addr[1])) + '.' + \
           str(ord(addr[2])) + '.' + \
           str(ord(addr[3]))


def get_default_iface_name_linux():
  route = "/proc/net/route"
  with open(route) as f:
    for line in f.readlines():
      try:
        iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
        if dest != '00000000' or not int(flags, 16) & 2:
          continue
        return iface
      except:
        continue

def get_public_facing_ip_nauca(distro):
  import neuca
  customizer = {
      "debian": neuca.NEucaLinuxCustomizer,
      "ubuntu": neuca.NEucaLinuxCustomizer,
      "redhat": neuca.NEucaLinuxCustomizer,
      "fedora": neuca.NEucaLinuxCustomizer,
      "centos": neuca.NEucaLinuxCustomizer,
      }.get(distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(distro)

  customizer.updateUserData()
  return customizer.getPublicIP()

def get_public_facing_ip_using_default_interface():
  public_iface = get_default_iface_name_linux()
  return get_ip_address(public_iface)

def get_public_facing_ip(args):
    if args.public_ip:
        return args.public_ip

    if args.nauca:
        try:
            return get_public_facing_ip_nauca(args.nauca)
        except:
            log.error('nauca get public ip failed, so trying to get ip of default interface')

    return get_public_facing_ip_using_default_interface()

def configure_arguments():
    parser = argparse.ArgumentParser(
        description="Allocates resources and creates ibp.cfg file"
        )
    parser.add_argument('--nauca', type=str, default=None,
                        help='Use nauca tools to get public ip. Provide distro name as parameter'
                        'Supported distributions are debian, ubuntu, redhat, centos, fedora.')
    parser.add_argument('--public_ip', type=str, default=None,
                        help='Specify public ip of the node. If specified utility will not attempt\
                        to guess the public IP.')
    parser.add_argument('-i', '--interfaces', type=str, default=None,
                        help='List of interfaces to bind to. If this option is not used then '
                              'all interfaces except localhost will be set. Specify multiple '
                              'interfaces by a comma separated list')
    parser.add_argument('--root', type=str, default=IBP_ROOT,
                        help='Specifies root path to /bin/ibp_server')
    parser.add_argument('--resource', type=str, default=IBP_RESOURCE_ROOT,
                        help='Specifies root path for resource allocations.')
    parser.add_argument('--force_allocate', action='store_true',
                        help='Ignores the resource lock and reallocates the resources.')
    parser.add_argument('-u', '--unis', action='store_true',
                        help='Unis registration entries are added.')
    parser.add_argument('-p', '--phoebus', type=str, default=None,
                        help='Specifies phoebus gateways separated by /.')
    parser.add_argument('--sleep', type=int, default=WAIT_INTERVAL,
                        help='Specifies time in seconds to wait before network interfaces have '
                        'come up.')
    parser.add_argument('--size', type=int, default=ALLOCATION_SIZE,
                        help='Specifies the max allocated size in MB for the resource')
    parser.add_argument('-l', '--log', action='store_true', help='Log to file.')
    args = parser.parse_args()

    #only either of nauca or public ip should be set
    if args.nauca and args.public_ip:
        log.error("both nauca or public ip should be used together")
        sys.exit(1)

    global c
    c = Configuration(args.root, args.resource, args.size)

    return args

def reallocation_needed(args):
    """
    We allocate resources when either lock file is not present or force_allocate flag is present
    """
    if args.force_allocate:
        return True

    if os.path.isfile(c.allocation_success_file()):
        log.info('This text file ({0}) acts as a lock for resource allocation. Delete it for '
        'reallocation!'.format(c.allocation_success_file()))
        return False
    else:
        log.info('This text file ({0}) not found, so allocating the '
                'resources'.format(c.allocation_success_file()))
        return True

def allocate(args):
    """
    Deletes resource directories and allocates them back
    """
    # check if already allocated
    if os.path.exists(c.resource_base_dir()):
        ret = query_yes_no("WARNING: directory %s already exists, delete?" % c.resource_base_dir())
        if ret:
            shutil.rmtree(c.resource_base_dir())
        else:
            log.error("Specify another resource path and try again, exiting.")
            exit(1)

    if os.path.exists(c.resource_db()):
      shutil.rmtree(c.resource_db())

    # now init the resources
    os.makedirs(c.resource_base_dir())
    os.makedirs(c.resource_db())
    resource = execute_command(c.makefs_cmd())

    # save resource for later runs
    with open(c.allocation_success_file(), 'w') as f:
      f.write(resource)

    return resource

def get_interface_addresses(args):
    """
    """
    interface_addresses = ""
    if args.interfaces:
        interfaces = args.interfaces.split(",")
        for ip in interfaces:
            interface_addresses += ip + ":" + str(IBP_PORT) + ";"
    else:
        for name, ip in all_interfaces():
            if name != "lo" or ip.startswith("127."):
                interface_addresses += format_ip(ip) + ":" + str(IBP_PORT) + ";"

    if interface_addresses == "":
        log.error("not even single interface address could be determined")
        sys.exit(1)

    return interface_addresses

def generate_config(args, interface_addresses, sub_ip_list, resource, public_ip):
    """
    """
    if resource == "":
        if os.path.isfile(c.allocation_success_file()):
            with open(c.allocation_success_file(), 'r') as f:
                resource = f.read()
        else:
            log.error("No resource allocation information found. Quitting...!")
            sys.exit(1)

    # create unis registration entry
    unis_config = ""
    if args.unis:
        use_ssl = 1 if UNIS_SSL_ENABLED else 0
        unis_config = UNIS_SAMPLE_CONFIG.format(unis_endpoint=UNIS_ENDPOINT, public_ip=public_ip,\
                                         cert_file_path=UNIS_SSL_CERT, key_file_path=UNIS_SSL_KEY,\
                                         use_ssl=use_ssl)

    # create phoebus entry
    phoebus_config = ""
    if args.phoebus:
        phoebus_config = PHOEBUS_SAMPLE_CONFIG.format(phoebus_gateway=args.phoebus)

    ibp_config = IBP_SAMPLE_CONFIG.format(interfaces=interface_addresses,
            substitute_map=sub_ip_list, phoebus=phoebus_config, resource=resource,
            unis=unis_config)

    # check that $IBP_ROOT/etc exists
    if not os.path.dirname(c.ibp_config_path()):
        os.makedirs(os.path.dirname(c.ibp_config_path()))

    with open(c.ibp_config_path(), 'w') as f:
        f.write(ibp_config)

    return ibp_config

def configure_logging(log_to_file):
    global log
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    if log_to_file:
        handler = logging.FileHandler(LOGFILENAME, 'a')
        handler.setFormatter(formatter)
        log.addHandler(handler)
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        log.addHandler(handler)


def main():
    # get arguments
    args = configure_arguments()

    #configure logging
    configure_logging(args.log)

    need_to_allocate = reallocation_needed(args)
    if need_to_allocate:
        resource = allocate(args)
    else:
        resource = ""

    log.info("To add more resources use 'bin/mkfs.resource <IBP id (unique)> dir <path to drive> <path to drive DB> <maximum size in MB>' command.\
 \n Then copy/paste the output from mkfs.resource  into the /etc/ibp.cfg. \n For more information check https://github.com/datalogistics/ibp_server  ")

    # Need to sleep because network prob fails if we do not wait for them
    log.info('Sleeping for %d seconds. This allows network interfaces to come up' % args.sleep)
    time.sleep(args.sleep)

    # generate interface addresses
    interface_addresses = get_interface_addresses(args)

    # get the public ip
    public_ip = get_public_facing_ip(args)

    # also prepare substitute_map option as 
    default_interface_ip = get_public_facing_ip_using_default_interface()
    sub_ip_list = default_interface_ip + ":" + public_ip + ";"

    #generate configuration file
    ibp_config = generate_config(args, interface_addresses, sub_ip_list, resource, public_ip)

    # start interface monitoring thread
    # execute_command(c.ibp_interface_monitor(), True)

    # bbye
    sys.exit(0)

if __name__ == "__main__":
    main()
