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
            self.sock_name = "/var/run/cpu_hotplug.sock"

        if self.args.listen:
            self.is_client = 0
        else:
            self.is_client = 1
        self.CONNECTION_MAGIC = 0xf8cb820d
        self.magic = pack('=L', self.CONNECTION_MAGIC)
        self.PROTOCOL_VERSION = 0x00000100
        self.prot_ver = pack('!L', self.PROTOCOL_VERSION)
        self.msg_types = {'EMPTY': 0, 'REQUEST': 1, 'REPLY': 2, 'COMPLETE': 3}
        self.msg_actions = {'ZERO': 0, 'DISCOVER': 1, 'UNPLUG': 2, 'PLUG': 3, 'GET_CURRENT_STATE': 4,
                            'SET_TARGET_STATE': 5, 'LAST': 6}
        self.errors = {'OK': 0, 'EINVAL': 2, 'MSG_TYPE': 3, 'MSG_VERSION': 4,
                       'NOT_HANDLED': 5, 'EBUSY': 6, 'EPERM': 7, 'NOT_IMPL': 8,
                       'ENOMEM': 9, 'EBADF': 10, 'ERANGE': 11}

    def server(self):
        try:
            os.remove(self.sock_name)
        except:
            pass
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.sock_name)
            self.sock.listen()
        except OSError:
            print("Error binding or listening to socket {}".format(self.sock_name))
            try:
                self.sock.close()
                os.remove(self.sock_name)
            except OSError:
                pass
            sys.exit(1)

        while True:
            try:
                new_sock, addr = self.sock.accept()
                self.server_rcv_send(new_sock)
            except OSError:
                print("Error reading raw message from socket")
                try:
                    new_sock.close()
                    self.sock.close()
                    os.remove(self.sock_name)
                except OSError:
                    pass
                sys.exit(1)

    def server_rcv_send(self, _sock):
        while True:
            buf = self.read_raw_message(_sock)
            if len(buf) == 0:
                _sock.close()
                return
            msg = self.unpack_raw_message(buf)
            self.print_unpacked_message(msg)
            self.dispatch_request(msg, _sock)

    def client(self):
        try:
            self.sock_connect(self.sock_name)
        except OSError:
            print("Error connecting to {}".format(self.sock_name))
            sys.exit(1)
        msg_dict = {'magic': self.CONNECTION_MAGIC,
                    'version': self.PROTOCOL_VERSION,
                    'msg_type': 1,
                    'cpu': 0,
                    'action': 0,
                    'current_state': 0,
                    'target_state': 0,
                    'result': 0,
                    'possible_mask': [0, 0, 0, 0, 0, 0, 0, 0],
                    'present_mask': [0, 0, 0, 0, 0, 0, 0, 0],
                    'online_mask': [0, 0, 0, 0, 0, 0, 0, 0],
                    'active_mask': [0, 0, 0, 0, 0, 0, 0, 0]}

        if True == self.args.discover:
            print("Sending a Discovery Request")
            msg_dict['action'] = self.msg_actions['DISCOVER']
        elif (self.args.unplug is True) and (self.args.cpu_list is not None):
            self.send_unplug_request(msg_dict, self.args.cpu_list)
            return
        elif (self.args.plug is True) and (self.args.cpu_list is not None):
            self.send_plug_request(msg_dict, self.args.cpu_list)
            return
        elif (self.args.get_state is True) and (self.args.cpu_list is not None):
            self.send_get_current_state_request(msg_dict, self.args.cpu_list)
            return
        elif (self.args.set_target is not None) and \
             (self.args.cpu_list is not None):
            self.send_set_target_state_request(msg_dict,
                                               self.args.cpu_list,
                                               self.args.set_target)
            return

        else:
            raise ParserError("Unsupported message action", self.errors['NOT_HANDLED'])
        msg = self.pack_message(msg_dict)
        self.write_packed_message(self.sock, msg)
        buf = self.read_raw_message(self.sock)
        self.sock.close()
        response = self.unpack_raw_message(buf)
        self.print_unpacked_message(response)

    def sock_connect(self, sock_name):
        print("Connecting to {}".format(sock_name))
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(sock_name)
        except OSError:
            print("Error connecting to socket {}".format(sock_name))
            raise
        return self.sock

    def pack_message(self, msg_dict):
        """ msg_dict is a dictionary """
        msg = bytearray(288)
        pack_into('=L', msg, 0, self.CONNECTION_MAGIC)
        pack_into('!L', msg, 4, self.PROTOCOL_VERSION)
        pack_into('=L', msg, 8, msg_dict['msg_type'])
        pack_into('=L', msg, 12, msg_dict['cpu'])
        pack_into('=L', msg, 16, msg_dict['action'])
        pack_into('=L', msg, 20, msg_dict['current_state'])
        pack_into('=L', msg, 24, msg_dict['target_state'])
        pack_into('=L', msg, 28, msg_dict['result'])
        offs = 32
        for q in msg_dict['possible_mask']:
            pack_into('=Q', msg, offs, q)
            offs += 8
        for q in msg_dict['present_mask']:
            pack_into('=Q', msg, offs, q)
            offs += 8
        for q in msg_dict['online_mask']:
            pack_into('=Q', msg, offs, q)
            offs += 8
        for q in msg_dict['active_mask']:
            pack_into('=Q', msg, offs, q)
            offs += 8
        return msg

    def print_packed_message(self, msg):
        print("{} {}", msg, len(msg))

    def print_unpacked_message(self, msg):
        print(msg)
    def write_packed_message(self, _sock, msg):
        try:
            print("sending {} bytes".format(len(msg)))
            _sock.sendall(msg)
        except OSError:
            print("Error writing packed message field to socket")

    def read_raw_message(self, _sock):
        try:
            buf = _sock.recv(288)
            print("Read {} bytes".format(len(buf)))
            return buf
        except OSError:
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
        cpu_possible_mask = unpack_from('=QQQQQQQQ', msg, 32)
        cpu_present_mask = unpack_from('=QQQQQQQQ', msg, 96)
        cpu_online_mask = unpack_from('=QQQQQQQQ', msg, 160)
        cpu_active_mask = unpack_from('=QQQQQQQQ', msg, 224)
        return {'magic': magic[0],
                'version': version[0],
                'msg_type': msg_type[0],
                'cpu': cpu[0],
                'action': action[0],
                'current_state': current_state[0],
                'target_state': target_state[0],
                'result': result[0],
                'possible_mask': cpu_possible_mask,
                'present_mask': cpu_present_mask,
                'online_mask': cpu_online_mask,
                'active_mask': cpu_active_mask}

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
            self.handle_unplug_request(request, _sock)
            return

        if request['action'] == self.msg_actions['PLUG']:
            self.handle_plug_request(request, _sock)
            return

        if request['action'] == self.msg_actions['GET_CURRENT_STATE']:
            self.handle_get_current_state(request, _sock)
            return

        if request['action'] == self.msg_actions['SET_TARGET_STATE']:
            self.handle_set_target_state(request, _sock)
            return

        raise ParserError("Request message not handled", self.errors['NOT_HANDLED'])

    def client_send_rcv(self, msg_dict):
        msg = self.pack_message(msg_dict)
        self.write_packed_message(self.sock, msg)
        buf = self.read_raw_message(self.sock)
        response = self.unpack_raw_message(buf)
        self.print_unpacked_message(response)

    def send_unplug_request(self, msg_dict, cpu_list):
        """msg_dict is a template for the request message,
           cpu_list is a list of the cpus to be unplugged"""
        for cpu in cpu_list:
            msg_dict['cpu'] = cpu
            msg_dict['action'] = self.msg_actions['UNPLUG']
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_unplug_request(self, msg_dict, _sock):
        print("Received a request to unplug cpu {}".format(msg_dict['cpu']))
        path = '/sys/devices/system/cpu/cpu{}/online'.format(msg_dict['cpu'])
        print(path)
        msg_dict['msg_type'] = self.msg_types['REPLY']
        try:
            with io.open(path, 'w', encoding = 'utf-8') as fp:
                print("open OK")
                fp.write('0')
            msg_dict['current_state'] = self.get_current_state(msg_dict['cpu'])
            msg_dict['result'] = self.errors['OK']
        except IOError:
            print("Error writing to {}".format(path))
            msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def send_plug_request(self, msg_dict, cpu_list):
        """msg_dict is a template for the request message,
           cpu_list is a list of the cpus to be unplugged"""
        for cpu in cpu_list:
            msg_dict['cpu'] = cpu
            msg_dict['action'] = self.msg_actions['PLUG']
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_plug_request(self, msg_dict, _sock):
        print("Received a request to plug in cpu {}".format(msg_dict['cpu']))
        path = '/sys/devices/system/cpu/cpu{}/online'.format(msg_dict['cpu'])
        print(path)
        msg_dict['msg_type'] = self.msg_types['REPLY']
        try:
            with io.open(path, 'w', encoding = 'utf-8') as fp:
                print("open OK")
                fp.write('1')
            msg_dict['current_state'] = self.get_current_state(msg_dict['cpu'])
            msg_dict['result'] = self.errors['OK']
        except IOError:
            print("Error writing to {}".format(path))
            msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def send_get_current_state_request(self, msg_dict, cpu_list):
        """msg_dict is a template for the request message,
           cpu_list is a list of the cpus to be unplugged"""
        msg_dict['action'] = self.msg_actions['GET_CURRENT_STATE']
        for cpu in cpu_list:
            print("sending for cpu {}".format(cpu))
            msg_dict['cpu'] = cpu
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_get_current_state(self, msg_dict, _sock):
        print("Received a request to get the current state of cpu {}".format(msg_dict['cpu']))
        msg_dict['msg_type'] = self.msg_types['REPLY']
        try:
            msg_dict['current_state'] = self.get_current_state(msg_dict['cpu'])
            msg_dict['result'] = self.errors['OK']
        except IOError:
            msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def send_set_target_state_request(self, msg_dict, cpu_list, target):
        """msg_dict is a template for the request message,
           cpu_list is a list of the cpus to be unplugged"""
        msg_dict['action'] = self.msg_actions['SET_TARGET_STATE']
        msg_dict['target_state'] = target[0]
        for cpu in cpu_list:
            print("sending for cpu {}".format(cpu))
            msg_dict['cpu'] = cpu
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_set_target_state(self, msg_dict, _sock):
        print("Received a request to set target state {} for cpu {}".format(msg_dict['target_state'],
                                                                            msg_dict['cpu']))
        msg_dict['msg_type'] = self.msg_types['REPLY']
        try:
            self.set_target_state(msg_dict['cpu'], msg_dict['target_state'])
            msg_dict['current_state'] = self.get_current_state(msg_dict['cpu'])
            msg_dict['result'] = self.errors['OK']
        except IOError:
            msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def get_current_state(self, cpu):
        path = '/sys/devices/system/cpu/cpu{}/hotplug/state'.format(cpu)
        print(path)
        current_state = None
        try:
            with io.open(path, 'r', encoding = 'utf-8') as fp:
                current_state = int(fp.read())
                fp.close()
        except IOError:
            print("Error reading from {}".format(path))
            raise IOError
        print("read current state {} for cpu {}".format(current_state, cpu))
        return current_state

    def set_target_state(self, cpu, target_state):
        path = '/sys/devices/system/cpu/cpu{}/hotplug/target'.format(cpu)
        print(path)
        try:
            with io.open(path, 'w', encoding = 'utf-8') as fp:
                print("writing {} to cpu {}".format(target_state, cpu))
                fp.write('{}'.format(target_state))
                fp.close()
        except IOError:
            print("Error writing {} to {}".format(target_state, path))
            print(IOError)
            raise IOError
        return target_state


def hotplug_main(args):
    usage_string = """usage: {} [...]""".format(sys.argv[0])
    parser = argparse.ArgumentParser(description=usage_string)
    parser.add_argument('--listen', action = 'store_true', help = 'listen for connections')
    parser.add_argument('--socket', action = 'store_true', help = 'path to domain socket')
    parser.add_argument('--discover', action = 'store_true', help = 'send a discovery request')
    parser.add_argument('--unplug', action = 'store_true', help = 'unplug one or more cpus')
    parser.add_argument('--plug', action = 'store_true', help = 'plug in one or more cpus')
    parser.add_argument('--get_state', action = 'store_true', help = 'get the current state of one or more cpus')
    parser.add_argument('--set_target', action = 'store', nargs = 1, type = int,
                        help = 'set the target state state for one or more cpus')
    parser.add_argument('--cpu_list', action = 'store', nargs = '*', type = int, help = 'list of one or more cpus')

    args = parser.parse_args()
    print(args)

    hotplug = HotPlug(args)
    if args.listen:
        try:
            hotplug.server()
        except KeyboardInterrupt:
            print("Exiting ...")
            hotplug.sock.close()
            os.remove(hotplug.sock_name)
            sys.exit(0)


    else:
        try:
            hotplug.client()
        except ParserError:
            parser.print_help()



if __name__ == "__main__":
    import argparse
    hotplug_main(sys.argv)
    sys.exit(0)
