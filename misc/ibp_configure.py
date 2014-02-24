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


IBP_PORT=6714
INSTALLATION_SUCCESS_FILE = "/root/.installed"
RESOURCE_DIR = "/root/ibp_resources/db"
RESOURCE_INIT_COMMAND = "/usr/local/bin/mkfs.resource database dir /root/ibp_resources/ /root/ibp_resources/db/ 8000"
IBP_CONFIG_FILE = "/usr/local/etc/ibp.cfg"
START_IBP_SERVER = "bash /usr/local/etc/init.d/ibp-server start"

ibp_sample_config = """
[server]
interfaces={}
lazy_allocate=1
threads=16
log_file=/var/log/ibp_server.log
password=ibp
phoebus_enable=0

#[phoebus]
#gateway=localhost/5006

{}

[unis]
name = IBP Server
type = ibp_server
endpoint = http://monitor.incntre.iu.edu:9000
init_register = 1
registration_interval = 120
publicip = {}
publicport = 6714

"""
def execute_command(cmd):
  print "Command to run:", cmd   ## good to debug cmd before actually running it
  (status, output) = commands.getstatusoutput(cmd)
  if status:    ## Error case, print the command's output to stderr and exit
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


if __name__ == "__main__":
  # Need to sleep because network prob fails if we do not wait for them
  time.sleep(60)

  # check if we have ran the script before
  if not os.path.isfile(INSTALLATION_SUCCESS_FILE):
    with open(INSTALLATION_SUCCESS_FILE, 'w') as f:
      f.write('This text file acts as a lock for installation script. Delete it to install it again.!')

    # get ip address of eth0
    #ip_address = get_ip_address("eth0")
    ip_address = ""
    for name, ip in all_interfaces():
        if name != "lo" or ip.startswith("127."):
            ip_address += format_ip(ip) + ":" + str(IBP_PORT) + ";"
    print ip_address
    if ip_address == "":
      print "eth0 interface could not be determined"
      sys.exit(1)

    # now init the resources
    os.makedirs(RESOURCE_DIR)
    output = execute_command(RESOURCE_INIT_COMMAND)

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
    #public_ip = execute_command("neuca-get-public-ip")
    public_ip = customizer.getPublicIP()

    #prepare config
    ibp_config = ibp_sample_config.format(ip_address, output, public_ip)
    with open(IBP_CONFIG_FILE, 'w') as f:
      f.write(ibp_config)

  sys.exit(0)
