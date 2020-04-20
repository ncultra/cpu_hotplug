#!/usr/bin/python3
import socket
import sys
import os
import subprocess
from struct import *
from array import *
import io

CONNECTION_MAGIC = pack('=L', 0xf8cb820f)
PROTOCOL_VERSION = pack('BBBB', 0, 0, 1, 0)

def pack_message(msg_type,
                 cpu,
                 action,
                 current_state = 0,
                 target_state = 0,
                 result = 0):
    msg = [CONNECTION_MAGIC,
           PROTOCOL_VERSION,
           pack('=L', msg_type),
           pack('=L', cpu),
           pack('=L', current_state),
           pack('=L', target_state),
           pack('=L', result)]
    return msg

def print_packed_message(msg):
    for field in msg:
        print(field)

message = pack_message(1, 2, 0)
print_packed_message(message)
