#!/usr/bin/env python
import socket
import fcntl
import struct
import sys
import os
import commands
import os.path
import time
import neuca
import array
import shutil


IBP_PORT=6714
ALLOCATION_SIZE = 8000  #mb
ALLOCATION_SUCCESS_FILE = "/root/.allocations_do_not_remove"
RESOURCE_BASE_DIR = "/root/ibp_resources"
RESOURCE_DB = RESOURCE_BASE_DIR + "/db"
RESOURCE_INIT_COMMAND = "/usr/local/bin/mkfs.resource database dir " + RESOURCE_BASE_DIR + " " + RESOURCE_DB + " " + str(ALLOCATION_SIZE)
IBP_CONFIG_FILE = "/usr/local/etc/ibp.cfg"
START_IBP_SERVER = "bash /usr/local/etc/init.d/ibp-server start"
START_IBP_INTERFACE_MONITOR = "/usr/local/bin/ibp_interface_monitor.py -l -d"

ibp_sample_config = """
# Do not modify this directly. It will loose change after service restart.
# Change in ibp_configure.py and then do 'service ibp-server restart'

[server]
interfaces={}
lazy_allocate=1
threads=16
log_file=/var/log/ibp_server.log
password=ibp

#[phoebus]
#gateway=localhost/5006

{}

[unis]
name = IBP Server
type = ibp_server
endpoint = http://monitor.incntre.iu.edu:9000
registration_interval = 120
publicip = {}
publicport = 6714

"""

def execute_command(cmd, ignore_status = False):
  print "Command to run:", cmd   ## good to debug cmd before actually running it
  (status, output) = commands.getstatusoutput(cmd)
  if status and not ignore_status:    ## Error case, print the command's output to stderr and exit
    sys.stderr.write(output)
    sys.exit(1)
  print output
  return output

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(),
      0x8915,  # SIOCGIFADDR
      struct.pack('256s', ifname[:15])
      )[20:24])

def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split('\0', 1)[0]
        ip   = namestr[i+20:i+24]
        lst.append((name, ip))
    return lst

def format_ip(addr):
    return str(ord(addr[0])) + '.' + \
           str(ord(addr[1])) + '.' + \
           str(ord(addr[2])) + '.' + \
           str(ord(addr[3]))


#TODO: after every restart check and see if ip has been changed and then update it
if __name__ == "__main__":
  resource = ""
  # check if we have allocated resources before
  if os.path.isfile(ALLOCATION_SUCCESS_FILE):
    print 'INFO: This text file ({}) acts as a lock for resource allocation. Delete it for reallocation.!'.format(ALLOCATION_SUCCESS_FILE)
  else:
    print 'INFO: This text file ({}) not found, so allocating the resources'.format(ALLOCATION_SUCCESS_FILE)

    # check if already allocated
    if os.path.exists(RESOURCE_BASE_DIR):
      shutil.rmtree(RESOURCE_BASE_DIR)

    if os.path.exists(RESOURCE_DB):
      shutil.rmtree(RESOURCE_DB)

    # now init the resources
    os.makedirs(RESOURCE_BASE_DIR)
    os.makedirs(RESOURCE_DB)
    resource = execute_command(RESOURCE_INIT_COMMAND)

    # save resource for later runs
    with open(ALLOCATION_SUCCESS_FILE, 'w') as f:
      f.write(resource)

  # Need to sleep because network prob fails if we do not wait for them
  time.sleep(60)

  # get ip address of eth0
  ip_address = ""
  for name, ip in all_interfaces():
      if name != "lo" or ip.startswith("127."):
          ip_address += format_ip(ip) + ":" + str(IBP_PORT) + ";"
  print ip_address

  if ip_address == "":
    print "even atleast eth0 interface could not be determined"
    sys.exit(1)

  # get the public ip
  distro = "debian"
  customizer = {
      "debian": neuca.NEucaLinuxCustomizer,
      "Ubuntu": neuca.NEucaLinuxCustomizer,
      "redhat": neuca.NEucaLinuxCustomizer,
      "fedora": neuca.NEucaLinuxCustomizer,
      "centos": neuca.NEucaLinuxCustomizer,
  }.get(distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(distro)
  
  customizer.updateUserData()
  public_ip = customizer.getPublicIP()

  #prepare config
  if resource == "":
    if os.path.isfile(ALLOCATION_SUCCESS_FILE):
      with open(ALLOCATION_SUCCESS_FILE, 'r') as f:
        resource = f.read()
    else:
      print "ERROR: No resource allocation information found. Quitting...!"
      sys.exit(1)
      
  ibp_config = ibp_sample_config.format(ip_address, resource, public_ip)
  with open(IBP_CONFIG_FILE, 'w') as f:
    f.write(ibp_config)

  execute_command(START_IBP_INTERFACE_MONITOR, True)
  sys.exit(0)
