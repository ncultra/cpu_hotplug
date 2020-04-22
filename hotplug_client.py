#!/usr/bin/python3
import socket
import sys
import os
import subprocess
from struct import *
import io

class ParserError(Exception):
    def __init__(self, message, errors):
        super(ParserError, self).__init__(message)
        self.error = error

class HotPlug:
    def __init__(self, args):
        self.args = args
        self.sock = 0
        if self.args.socket:
            self.sock_name = args.socket
        else:
            self.sock_name = "/var/run/cpu_hotplug"

        if self.args.listen:
            self.is_client = 0
        else:
            self.is_client = 1
        self.CONNECTION_MAGIC = 0xf8cb820f
        self.magic = pack('=L', self.CONNECTION_MAGIC)
        self.PROTOCOL_VERSION = 0x00000100
        self.prot_ver = pack('!L', self.PROTOCOL_VERSION)
        self.msg_types = {'EMPTY': 0, 'REQUEST': 1, 'REPLY': 2, 'COMPLETE': 3}
        self.msg_actions = {'ZERO': 0, 'DISCOVER': 1, 'UNPLUG': 2, 'PLUG': 3,
                            'GET_CURRENT_STATE': 4, 'SET_TARGET_STATE': 5, 'LAST': 6}
        self.errors = {'OK': 0, 'EINVAL': 2, 'MSG_TYPE': 3, 'MSG_VERSION': 4,
                       'NOT_HANDLED': 5}

    def server(self):
        os.remove(self.sock_name)
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.sock_name)
            self.sock.listen()
        except socket.error:
            print("Error binding or listening to socket {}".format(self.sock_name))

        while True:
            try:
                new_sock, addr = self.sock.accept()
                buf = self.read_raw_message(new_sock)
            except socket.error:
                print("Error reading raw message from socket")
                new_sock.close()
                self.sock.close()

            msg = self.unpack_raw_message(buf)
            self.print_unpacked_message(msg)
            self.dispatch_request(msg, new_sock)

            new_sock.close()

    def client(self):
        self.sock_connect(self.sock_name)
        msg_dict = {'magic': self.CONNECTION_MAGIC,
                    'version': self.PROTOCOL_VERSION,
                    'msg_type': 1,
                    'cpu': 0,
                    'action': 0,
                    'current_state': 0,
                    'target_state': 0,
                    'result': 0}

        if True == self.args.discover:
            print("Sending a Discovery Request")
            msg_dict['action'] = self.msg_actions['DISCOVER']
        else:
            raise ParserError("Unsupported message action", self.errors['NOT_HANDLED'])
        msg = self.pack_message(msg_dict)
        self.write_packed_message(self.sock, msg)
        buf = self.read_raw_message(self.sock)
        self.sock.close()
        response = self.unpack_raw_message(buf)
        self.print_unpacked_message(response)


    def sock_connect(self, sock_name):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print("Connecting to {}".format(sock_name))
        try:
            self.sock.connect(sock_name)
        except socket.error:
            print("Error connecting to socket {}".format(sock_name))
        return self.sock

    def pack_message(self, msg_dict):
        """ msg_dict is a dictionary """
        print(msg_dict)
        msg = bytearray(36)
        pack_into('=L', msg, 0, self.CONNECTION_MAGIC)
        pack_into('!L', msg, 4, self.PROTOCOL_VERSION)
        pack_into('=L', msg, 8, msg_dict['msg_type'])
        pack_into('=L', msg, 12, msg_dict['cpu'])
        pack_into('=L', msg, 16, msg_dict['action'])
        pack_into('=L', msg, 20, msg_dict['current_state'])
        pack_into('=L', msg, 24, msg_dict['target_state'])
        pack_into('=L', msg, 28, msg_dict['result'])
        return msg

    def print_packed_message(self, msg):
        print("{} {}", msg, len(msg))

    def print_unpacked_message(self, msg):
        print(msg)
    def write_packed_message(self, _sock, msg):
        try:
            print("sending {} bytes".format(len(msg)))
            _sock.sendall(msg)
        except socket.error:
            print("Error writing packed message field to socket")

    def read_raw_message(self, _sock):
        try:
            buf = _sock.recv(36)
            print("Read {} bytes".format(len(buf)))
            return buf
        except socket.error:
            print("Error reading bytes from socket")


    def unpack_raw_message(self, msg):
        """returns a dictionary with message fields"""
        magic = unpack_from('=L', msg, 0)
        version = unpack_from('!L', msg, 4)
        msg_type = unpack_from('=L', msg, 8)
        cpu = unpack_from('=L', msg, 12)
        action = unpack_from('=L', msg, 16)
        current_state = unpack_from('=L', msg, 20)
        target_state = unpack_from('=L', msg, 24)
        result = unpack_from('=L', msg, 28)
        return {'magic': magic[0],
                'version': version[0],
                'msg_type': msg_type[0],
                'cpu': cpu[0],
                'action': action[0],
                'current_state': current_state[0],
                'target_state': target_state[0],
                'result': result[0]}

    def check_magic(self, magic):
        if magic == self.CONNECTION_MAGIC:
            return True
        else:
            return False

    def check_version(self, version):
        if version == self.PROTOCOL_VERSION:
            return True
        else:
            return False

    def dispatch_request(self, request, _sock):
        """request is a dictionary containing unpacked message fields"""
        # first check the header and type
        if False == self.check_magic(request['magic']):
            raise ParserError("Bad message header", self.errors['EINVAL'])
        if False == self.check_version(request['version']):
            raise ParserError("Bad message protocol version", self.errors['MSG_VERSION'])
        if request['msg_type'] != self.msg_types['REQUEST']:
            raise ParserError("Wrong message type", self.errors['MSG_TYPE'])

        # the header and type are good, see if we can dispatch the message
        if request['action'] == self.msg_actions['DISCOVER']:
            # respond with a copy of this message (as a reply type)
            request['msg_type'] = self.msg_types['REPLY']
            reply = self.pack_message(request)
            self.write_packed_message(_sock, reply)
            return

        if request['action'] == self.msg_actions['UNPLUG']:
            request['msg_type'] = self.msg_types['REPLY']
            request['result'] = self.errors['OK']
            reply = self.pack_message(request)
            print("Received a request to unplug cpu {}", request['cpu'])
            self.write_packed_message(_sock, reply)
            return

        raise ParserError("Request message not handled", self.errors['NOT_HANDLED'])

def hotplug_main(args):
    usage_string = """usage: {} [...]""".format(sys.argv[0])
    parser = argparse.ArgumentParser(description=usage_string)
    parser.add_argument('--listen', action = 'store_true', help = 'listen for connections')
    parser.add_argument('--socket', action = 'store_true', help = 'path to domain socket')
    parser.add_argument('--discover', action = 'store_true', help = 'send a discovery request')

    args = parser.parse_args()

    hotplug = HotPlug(args)
    if args.listen:
        hotplug.server()
    else:
        hotplug.client()

if __name__ == "__main__":
    import argparse
    hotplug_main(sys.argv)
    sys.exit(0)
