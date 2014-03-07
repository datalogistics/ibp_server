#!/usr/bin/env python

"""
Interface monitor for IBP server.

Currently we do not have any way to accomodate interface changes during run time.
This is hack which restarts the server if there is any changes in network interfaces.
"""

import sys
import time
import daemon
import argparse
import ConfigParser
import logging
import socket
import fcntl
import struct
import os
import commands
import os.path
import array
import shutil

IBP_PID_LOCATION = "/usr/local/bin/var/run/ibp_server.pid"
IBP_SERVER_INIT_COMMAND = "service ibp-server restart"
IBP_MONITOR_SCRIPT_PID_LOCATION = "/var/run/ibp_interface_monitor.pid"

stored_interfaces = set()

class IBPIntMonException(Exception):
  def __init__(self, message):
    self.msg = message
    Exception.__init__(self)

    def __str__(self):
      return "IBPIntMonException: " + self.msg

def execute_command(cmd):
  logging.info("Command to run: %s"% (cmd))   ## good to debug cmd before actually running it
  (status, output) = commands.getstatusoutput(cmd)
  if status:    ## Error case, print the command's output to stderr and exit
    raise IBPIntMonException("Could not execute the command: %s" % (cmd))
  logging.info("%s:%s" % (cmd, output))
  return output

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


def check_pid(pid):        
  """ Check For the existence of a unix pid. """
  try:
    os.kill(pid, 0)
  except OSError:
    return False
  else:
    return True


def check_interfaces():
  # get ip address of eth0
  current_interfaces = set()
  global stored_interfaces

  for name, ip in all_interfaces():
    if name != "lo" or ip.startswith("127."):
      current_interfaces.add(format_ip(ip))

  logging.info("current_interfaces {}".format(current_interfaces))

  if len(current_interfaces) == 0:
    logging.warn("even atleast eth0 interface could not be determined")
    return

  #if this is first time then update and continue
  if len(stored_interfaces) == 0:
    stored_interfaces |= current_interfaces
    logging.info("stored_interfaces {}".format(stored_interfaces))
  else:
    #check whether we have any changes in the interface
    if len(stored_interfaces.difference(current_interfaces)) != 0:
      #we have changes in interfaces, restart the service.
      logging.info("Network interfaces have been changed. Restarting the service to reflect it")
      logging.info("stored_interfaces {}".format(stored_interfaces))
      logging.info("current_interfaces {}".format(current_interfaces))
      # check if we have ibp_server running otherwise forget about it
      if os.path.isfile(IBP_PID_LOCATION):
        with open(IBP_PID_LOCATION, 'r') as f:
          pid = f.read()
          if check_pid(int(pid)):
            execute_command(IBP_SERVER_INIT_COMMAND)

def configure_logging(log):
  logging.basicConfig(level=logging.DEBUG, filename="/var/log/ibp_interface_monitor.log", format='[%(levelname)s] %(message)s')
  if not log:
    handler_stream = logging.StreamHandler()
    logging.getLogger().addHandler(handler_stream)

def main_loop():
  with open(IBP_MONITOR_SCRIPT_PID_LOCATION, 'w') as f:
    f.write(str(os.getpid()))

  while True:
    try:
      check_interfaces()
    except Exception as e:
      logging.error(e)
    #todo change time
    time.sleep(5)

def check_if_already_running():
  if os.path.isfile(IBP_MONITOR_SCRIPT_PID_LOCATION):
    with open(IBP_MONITOR_SCRIPT_PID_LOCATION, 'r') as f:
      pid = f.read()
      if check_pid(int(pid)):
        print("Quitting, as another instance is running")
        sys.exit(0)

def main():
  check_if_already_running()

  parser = argparse.ArgumentParser(
      description="Network Interface Monitor for IBP_Server")
  parser.add_argument('-d', '--daemon', action='store_true',
      help='Daemonize the monitoring process')
  parser.add_argument('-l', '--logging', action='store_true',
      help='log to Log file instead of stdout.')
  args = parser.parse_args()

  if args.daemon:
      with daemon.DaemonContext():
        configure_logging(args.logging)
        main_loop()
  else:
    configure_logging(args.logging)
    main_loop()

if __name__ == '__main__':
  main()
  sys.exit(0)
