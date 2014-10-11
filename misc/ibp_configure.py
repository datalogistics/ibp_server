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

MS_URL = "https://dlt.incntre.iu.edu:9001"
IBP_CONFIG_LOG = "ibp_configure.log"

IBP_SAMPLE_CONFIG = """
# Do not modify this directly. It will loose change after service restart.
# Change in ibp_configure.py and then do 'service ibp-server restart'

[server]
interfaces={interfaces}
lazy_allocate=1
threads=16
log_file={ibp_log}
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
publicport = {port}
use_ssl = {use_ssl}
client_certfile = {cert_file}
client_keyfile = {key_file}
institution = {inst}
country = {country}
state = {state}
zipcode = {zipcode}
latitude = {lat}
longitude = {lon}
"""

BLIPP_CONFIG = """
{
    "status": "ON",
    "serviceType": "ps:tools:blipp",
    "name": "blipp",
    "ttl": 100000,
    "location": {
        "institution": %s,
        "street_address": %s,
        "state": %s,
        "zipcode": %s,
        "country": %s,
        "latitude": %f.
        "longitude": %f
    },
    "description": "BLiPP for DLT Install",
    "properties": {
      "configurations": {
        "unis_url": %s,
        "use_ssl": %s,
            "ssl_cert": %s,
            "ssl_key": %s,
        "ssl_cafile": "",
        "probe_defaults":
        {"collection_schedule":"builtins.simple",
         "schedule_params": {"every": 2},
         "reporting_params": 8,
         "collection_size":100000,
         "collection_ttl":1500000,
         "ms_url": MS_URL
        },
        "probes":{
                "ibp_server": {
                    "probe_module": "cmd_line_probe",
                    "command": "get_version %s %d",
                    "regex": "Total resources.*Used:\\s+(?P<used>\\d+).*Free:\\s+(?P<free>\\d+).*",
                    "eventTypes": {"used": "ps:tools:blipp:ibp_server:resource:usage:used",
                                   "free": "ps:tools:blipp:ibp_server:resource:usage:free"}
                }
        }
      },
    }
}
"""

class System():
    def execute_command(self, cmd, ignore_status = False):
        log.debug("Executing command: %s" % cmd)
        (status, output) = commands.getstatusoutput(cmd)
        if status and not ignore_status:
            log.error(output)
            sys.exit(1)
        return output

    def get_ip_address(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    
    def all_interfaces(self):
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

    def format_ip(self, addr):
        return str(ord(addr[0])) + '.' + \
            str(ord(addr[1])) + '.' + \
            str(ord(addr[2])) + '.' + \
            str(ord(addr[3]))


    def get_default_iface_name_linux(self):
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

    def get_public_facing_ip_neuca(self, distro):
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

    def get_public_facing_ip_using_default_interface(self):
        public_iface = self.get_default_iface_name_linux()
        return self.get_ip_address(public_iface)

    def get_public_facing_ip(self, args):
        if args.host:
            return args.host

        if args.neuca:
            try:
                return self.get_public_facing_ip_neuca(args.neuca)
            except:
                log.error('neuca get public ip failed, so trying to get ip of default interface')

        return self.get_public_facing_ip_using_default_interface()

class Configuration():
    def __init__(self):
        # init sets config defaults
        self.wait_interval     = 10
        self.enable_blipp      = False
        self.phoebus           = ""
        self.unis_endpoint     = "https://dlt.incntre.iu.edu:9000"
        self.unis_use_ssl      = True
        self.unis_cert_file    = "/usr/local/etc/dlt-client.pem"
        self.unis_key_file     = "/usr/local/etc/dlt-client.key"
        self.unis_institution  = ""
        self.unis_street       = ""
        self.unis_zipcode      = ""
        self.unis_country      = ""
        self.unis_latitude     = 0
        self.unis_longitude    = 0
        self.ibp_size          = 8000
        self.ibp_port          = 6714
        self.ibp_resource_path = "/tmp/ibp_resources"
        self.ibp_resource_db   = "/tmp/ibp_resources/db"
        self.ibp_root          = "/"
        self.ibp_log           = "/var/log/ibp_server.log"
        
    def allocation_success_file(self):
        # acts as lock for reallocation. This file will be created when resources are
        # allocated for ibp_server. If this file is removed then resources will be
        # reallocated (and all original data will be lost)
        return os.path.join(self.ibp_resource_path, ".allocations_do_not_remove")

    def makefs_cmd(self):
        return path.join(self.ibp_root, "bin/mkfs.resource") + " 0 dir " + self.ibp_resource_path\
               + " " + self.ibp_resource_db + " " + str(self.ibp_size)

    def ibp_config_file(self):
        return path.join(self.ibp_root, "etc/ibp.cfg")

    def ibp_interface_monitor(self):
        return path.join(self.ibp_root, "bin/ibp_interface_monitor.py") + " -l -d"

    def query_yes_no(self, question, default="no"):
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

    def get_ibp_interface_addresses(self, args):
        """
        """
        interface_addresses = ""
        if args.interfaces:
            interfaces = args.interfaces.split(",")
            for ip in interfaces:
                interface_addresses += ip + ":" + str(self.ibp_port) + ";"
        else:
            for name, ip in mysys.all_interfaces():
                if name != "lo" or ip.startswith("127."):
                    interface_addresses += mysys.format_ip(ip) + ":" + str(self.ibp_port) + ";"

        if interface_addresses == "":
            log.error("not even single interface address could be determined")
            sys.exit(1)

        return interface_addresses

    def reallocation_needed(self, args):
        """
        We allocate resources when either lock file is not present or force_allocate flag is present
        """
        if args.force_allocate:
            return True
    
        if os.path.isfile(self.allocation_success_file()):
            log.info('This text file ({0}) acts as a lock for resource allocation.\nDelete it for '
                     'reallocation!'.format(self.allocation_success_file()))
            return False
        else:
            log.info('This text file ({0}) not found, so allocating the '
                     'resources'.format(self.allocation_success_file()))
        return True

    def allocate(self, args):
        """
        Deletes resource directories and allocates them back
        """
        if not self.reallocation_needed(args):
            with open(self.allocation_success_file(), 'r') as f:
                return f.read()

        # check if already allocated
        if os.path.exists(self.ibp_resource_path):
            ret = self.query_yes_no("WARNING: directory %s already exists, delete?" %
                                    self.ibp_resource_path)
            if ret:
                shutil.rmtree(self.ibp_resource_path)
            else:
                log.error("Specify another resource path and try again, exiting.")
                exit(1)
                
        if os.path.exists(self.ibp_resource_db):
            ret = self.query_yes_no("WARNING: directory %s already exists, delete?" %
                                    self.ibp_resource_db)
            if os.path.exists(self.ibp_resource_db):
                shutil.rmtree(self.ibp_resource_db)

        # now init the resources
        os.makedirs(self.ibp_resource_path)
        os.makedirs(self.ibp_resource_db)
        resource = mysys.execute_command(self.makefs_cmd())

        # save resource for later runs
        with open(self.allocation_success_file(), 'w') as f:
            f.write(resource)

        return resource

    def get_string(self, disp_str, dval):
        val = raw_input(disp_str)
        if len(str(val)):
            return str(val)
        else:
            return dval

    def get_int(self, disp_str, dval):
        val = raw_input(disp_str)
        try:
            rval = int(val)
            return rval
        except:
            return dval

    def get_real(self, disp_str, dval):
        val = raw_input(disp_str)
        try:
            rval = float(val)
            return rval
        except:
            return dval

    def get_user_input(self, args):
        public_ip = mysys.get_public_facing_ip(args)

        print "==============================================================="
        print ":: Begin interactive DLT configuration"

        print "\n== IBP Server Settings =="
        self.ibp_host = self.get_string('IBP hostname [%s]: ' % public_ip, public_ip) 
        self.ibp_port = self.get_int('IBP port [%s]: ' % self.ibp_port, self.ibp_port)
        self.ibp_resource_path = self.get_string('Resource path [%s] ' %
                                                 self.ibp_resource_path, self.ibp_resource_path)
        self.ibp_resource_db = self.get_string('Resource DB path [%s] ' %
                                                 self.ibp_resource_db, self.ibp_resource_db)
        self.ibp_size = self.get_int('Total disk space [%s MB] ' % self.ibp_size, self.ibp_size)
        self.ibp_log = self.get_string('IBP log file [%s] ' % self.ibp_log, self.ibp_log)
        print "\n== UNIS Settings (depot registration) =="
        self.unis_endpoint = self.get_real('UNIS URL [%s]: ' % self.unis_endpoint, self.unis_endpoint)
        self.unis_use_ssl = self.query_yes_no('Enable SSL', default="yes")
        if self.unis_use_ssl:
            self.unis_cert_file = self.get_string('UNIS client cert file [%s]: ' %
                                                  self.unis_cert_file, self.unis_cert_file)
            self.unis_key_file = self.get_string('UNIS client key file [%s]: ' %
                                                 self.unis_key_file, self.unis_key_file)
        self.unis_institution = self.get_string('Institution [%s]: ' % self.unis_institution,
                                                self.unis_institution)
        self.unis_country = self.get_string('Country [%s]: ' % "US", "US")
        self.unis_state = self.get_string('State [%s]: ' % "AK", "AK")
        self.unis_zipcode = self.get_string('ZipCode [%s]: ' % "00000", "00000")
        self.unis_latitude = self.get_real('Latitude [%s]: ' % self.unis_latitude, self.unis_latitude) 
        self.unis_longitude = self.get_real('Longitude [%s]: ' % self.unis_longitude, self.unis_longitude) 
        self.enable_blipp = self.query_yes_no('Monitor the depot with BLiPP (usage stats)', default='yes')
        print "\n== Phoebus Settings (WAN Acceleration) =="
        self.phoebus = self.get_string('Optional Phoebus Gateway (<host>/<port>): ', '')
        
    def generate_config(self, args):
        """
        """
        resource_config = self.allocate(args)

        if self.phoebus == "":
            phoebus_config = ""
        else:
            phoebus_config = PHOEBUS_SAMPLE_CONFIG.format(phoebus_gateway=self.phoebus)

        if resource_config == "":
            if os.path.isfile(self.allocation_success_file()):
                with open(self.allocation_success_file(), 'r') as f:
                    resource = f.read()
            else:
                log.error("No resource allocation information found. Quitting...!")
                sys.exit(1)

        if len(self.ibp_host):
            ibp_conn_strings = self.ibp_host + ':' + str(self.ibp_port)
        else:
            ibp_conn_strings = self.get_ibp_interface_addresses(args)

        # also prepare substitute_map option as 
        default_interface_ip = mysys.get_public_facing_ip_using_default_interface()
        sub_ip_list = default_interface_ip + ":" + self.ibp_host + ";"

        unis_config = UNIS_SAMPLE_CONFIG.format(unis_endpoint=self.unis_endpoint,
                                                public_ip=self.ibp_host,
                                                port=self.ibp_port,
                                                use_ssl=self.unis_use_ssl,
                                                cert_file=self.unis_cert_file,
                                                key_file=self.unis_key_file,
                                                inst=self.unis_institution,
                                                state=self.unis_state,
                                                zipcode=self.unis_zipcode,
                                                country=self.unis_country,
                                                lat=self.unis_latitude,
                                                lon=self.unis_longitude)

        ibp_config = IBP_SAMPLE_CONFIG.format(interfaces=ibp_conn_strings,
                                              ibp_log=self.ibp_log,
                                              substitute_map=sub_ip_list,
                                              phoebus=phoebus_config,
                                              resource=resource_config,
                                              unis=unis_config)

        # check that $IBP_ROOT/etc exists
        if not os.path.dirname(self.ibp_config_file()):
            os.makedirs(os.path.dirname(self.ibp_config_file()))

        if os.path.isfile(self.ibp_config_file()):
            with open(self.ibp_config_file(), 'r') as f:
                with open(self.ibp_config_file()+".ibp_configure_save", 'w') as g:
                          g.write(f.read())
                          g.close()
                          f.close()

        with open(self.ibp_config_file(), 'w') as f:
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


mysys = System()

def main():
    parser = argparse.ArgumentParser(
        description="Allocates resources and creates ibp.cfg file")
    parser.add_argument('--neuca', type=str, default=None,
                        help='Use neuca tools to get public ip. Provide distro name as parameter'
                        'Supported distributions are debian, ubuntu, redhat, centos, fedora.')
    parser.add_argument('--force_allocate', action='store_true',
                        help='Ignores the resource lock and reallocates the resources.')
    parser.add_argument('--host', type=str, default=None,
                        help='Specify hostname or IP of the node. If specified this script will not attempt\
                        to guess the public IP.')
    parser.add_argument('-i', '--interfaces', type=str, default=None,
                        help='List of interfaces to bind to. If this option is not used then '
                              'all interfaces except localhost will be set. Specify multiple '
                              'interfaces by a comma separated list')
    parser.add_argument('-l', '--log', action='store_true', help='Log to file.')
    args = parser.parse_args()

    #only either of neuca or public ip should be set
    if args.neuca and args.host:
        log.error("both neuca or public ip should be used together")
        sys.exit(1)

    configure_logging(args.log)

    cfg = Configuration()
    cfg.get_user_input(args)
    ibp_config = cfg.generate_config(args)

    #print ibp_config

    # start interface monitoring thread
    # execute_command(c.ibp_interface_monitor(), True)

    # bbye
    sys.exit(0)

if __name__ == "__main__":
    main()
