#!/usr/bin/python3
import sys
import os
from subprocess import *
import uuid
import argparse
import time
from hotplug_client import *

#    stress -t 10 -c 4 -i 4 -m 4 -d 4
def run_stress(count, timeout):
    Popen(["/usr/bin/stress",
           "-t", "{}".format(timeout),
           "-c", "{}".format(count),
           "-i", "{}".format(count),
           "-m", "{}".format(count),
           "-d", "{}".format(count)])

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



def unplug_cpus(cpu_list, interval, _uuid):
    print(cpu_list)
    print(interval)
    hp_args = empty_args()
    hp_args['unplug'] = True
    hp_args['uuid'] = _uuid
    hp_args['socket'] = "/var/run/cpu_hotplug.sock"
    for cpu in cpu_list:
        time.sleep(interval)
        hp_args['cpu_list'] = [cpu]
        print(hp_args)
        hotplug = HotPlug(hp_args)
        try:
            print("unplugging {}".format(cpu))
            hotplug.client()
        except ParserError:
            parser.print_help()

def plug_cpus(cpu_list, interval, _uuid):
    hp_args = empty_args()
    hp_args['plug'] = True
    hp_args['uuid'] = _uuid
    hp_args['socket'] = "/var/run/cpu_hotplug.sock"
    for cpu in cpu_list:
        time.sleep(interval)
        hp_args['cpu_list'] = [cpu]
        hotplug = HotPlug(hp_args)
        try:
            print("re-plugging {}".format(cpu))
            hotplug.client()
        except ParserError:
            parser.print_help()

def shell_main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu_list', action = 'store', nargs = '*', type = int, help = 'list of one or more cpus')
    parser.add_argument('--cpu_count', action = 'store', nargs = 1, type = int)
    parser.add_argument('--stress_timeout', action = 'store', nargs = 1, type = int)
    parser.add_argument('--cpu_interval', action = 'store', nargs = 1, type = int)
    parser.add_argument('--uuid', action = 'store', nargs = 1)
    vargs = vars(parser.parse_args())
    print(vargs)
    run_stress(vargs['cpu_count'][0], vargs['stress_timeout'][0])
    unplug_cpus(vargs['cpu_list'], vargs['cpu_interval'][0], vargs['uuid'])
    plug_cpus(vargs['cpu_list'], vargs['cpu_interval'][0], vargs['uuid'])
if __name__ == "__main__":
    shell_main(sys.argv)
    sys.exit(0)
