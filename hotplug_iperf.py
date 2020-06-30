#!/usr/bin/python3
import sys
import os
from subprocess import *
import uuid
import argparse
import time
from hotplug_client import *

def empty_args():
    empty =  {'listen': False,
              'socket': False,
              'discover': False,
              'unplug': False,
              'plug': False,
              'get_boot_state': False,
              'get_state': False,
              'get_bitmasks': False,
              'set_target': None,
              'map_length': None,
              'uuid': None,
              'cpu_list': None}
    return empty

# iperf3 -c 10.0.1.3 -P 8 -t 10 -i 10
def run_iperf(server, cpu_list, cpu_count, cpu_interval, _uuid):
    hp_args = empty_args()
    hp_args['unplug'] = True
    hp_args['uuid'] = _uuid
    hp_args['socket'] = "/var/run/cpu_hotplug.sock"
    for cpu in cpu_list:
        iperf_proc = Popen(["/usr/bin/iperf3",
                           "-c", server,
                           "-P", "{}".format(cpu_count),
                           "-t", "{}".format(cpu_interval),
                           "-i", "{}".format(cpu_interval)])
        iperf_proc.wait()
        hp_args['cpu_list'] = [cpu]
        hotplug = HotPlug(hp_args)
        try:
            print("unplugging {}".format(cpu))
            hotplug.client()
        except ParserError:
            parser.print_help()

    for cpu in cpu_list:


def iperf_main(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('--cpu_list', action = 'store', nargs = '*', type = int, help = 'list of one or more cpus')
    parser.add_argument('--cpu_count', action = 'store', nargs = 1, type = int)
    parser.add_argument('--cpu_interval', action = 'store', nargs = 1, type = int)
    parser.add_argument('--uuid', action = 'store', nargs = 1)
    parser.add_argument('--server', action = 'store', nargs = 1)
    vargs = vars(parser.parse_args())
    print(vargs)

if __name__ == "__main__":
    iperf_main(sys.argv)
    sys.exit(0)
