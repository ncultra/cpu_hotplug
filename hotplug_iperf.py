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
    total_time = (count + 1) * timeout
    print("total stress time: {}".format(total_time))
    stress_test = Popen(["/usr/bin/stress",
                         "-t", "{}".format(total_time),
                         "-c", "{}".format(count),
                         "-i", "{}".format(count),
                         "-m", "{}".format(count),
                         "-d", "{}".format(count)])
    return stress_test

# iperf3 -c 10.0.1.3 -P 8 -t 10 -i 10
def run_iperf(server, cpu_list, cpu_count, cpu_interval, _uuid):
    hp_args = empty_args()
    hp_args['unplug'] = True
    hp_args['uuid'] = _uuid
    hp_args['socket'] = "/var/run/cpu_hotplug.sock"
    iperf_proc = Popen(["/usr/bin/iperf3",
                        "-c", "{}".format(server),
                        "-P", "{}".format(cpu_count),
                        "-t", "{}".format(cpu_interval),
                        "-i", "{}".format(cpu_interval)])
    iperf_proc.wait()
    for cpu in cpu_list:
        hp_args['cpu_list'] = [cpu]
        hotplug = HotPlug(hp_args)
        try:
            print("unplugging {}".format(cpu))
            hotplug.client()
        except ParserError:
            parser.print_help()
        iperf_proc = Popen(["/usr/bin/iperf3",
                            "-c", "{}".format(server),
                            "-P", "{}".format(cpu_count),
                            "-t", "{}".format(cpu_interval),
                            "-i", "{}".format(cpu_interval)])
        iperf_proc.wait()

    hp_args['unplug'] = False
    hp_args['plug'] = True
    for cpu in cpu_list:
        hp_args['cpu_list'] = [cpu]
        hotplug = HotPlug(hp_args)
        try:
            print("re-plugging {}".format(cpu))
            hotplug.client()
        except ParserError:
            parser.print_help()

def iperf_main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu_list', action = 'store', nargs = '*', type = int, \
                        help = 'list of one or more cpus')
    parser.add_argument('--cpu_count', action = 'store', nargs = 1, type = int)
    parser.add_argument('--cpu_interval', action = 'store', nargs = 1, type = int)
    parser.add_argument('--uuid', action = 'store', nargs = 1)
    parser.add_argument('--server', action = 'store', nargs = 1)
    parser.add_argument('--stress', action = 'store_true', \
                        help = "run stress in the background") 
    vargs = vars(parser.parse_args())
    print(vargs)
    if vargs['stress'] is True:
        stress_ret = run_stress(vargs['cpu_count'][0],
                                vargs['cpu_interval'][0])

    run_iperf(vargs['server'][0],
              vargs['cpu_list'],
              vargs['cpu_count'][0],
              vargs['cpu_interval'][0],
              vargs['uuid'])
if __name__ == "__main__":
    iperf_main(sys.argv)
    sys.exit(0)
