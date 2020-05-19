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
        """Initialize the HotPlug object.

        Arguments determine whether the object is a client or server, and the
        name of the Unix domain socket file. Server mode is active when the
        --listen argument is present.

        The remainder of the initialization involves message header variables
        and Dictionaries for message types, actions, and errors.
        """
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
        self.msg_actions = {'ZERO': 0, 'DISCOVER': 1, 'UNPLUG': 2, 'PLUG': 3,
                            'GET_BOOT_STATE': 4, 'GET_CURRENT_STATE': 5,
                            'SET_TARGET_STATE': 6, 'GET_CPU_BITMASKS': 7, 'LAST': 8}
        self.errors = {'OK': 0, 'EINVAL': 2, 'MSG_TYPE': 3, 'MSG_VERSION': 4,
                       'NOT_HANDLED': 5, 'EBUSY': 6, 'EPERM': 7, 'NOT_IMPL': 8,
                       'ENOMEM': 9, 'EBADF': 10, 'ERANGE': 11}

    def server(self):
        """Listen for socket connections and respond to hotplug messages.

        Server mode is activated by passing the --listen parameter on the command line
        when run in command line mode.

        Creates a Unix domain socket, binds the socket to self.sock_name, and listens
        for connections. For each connection, calls accept to create a new socket,
        and enters a send-receive loop using that socket.
        """
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
        """Server send/receive loop.

        Reads and requests dispatches, sends replies. When the client stops sending
        messages, exit the loop.

        Messages are in binary format, and must be unpacked into a Dictionary.
        """
        while True:
            buf = self.read_raw_message(_sock)
            if len(buf) == 0:
                _sock.close()
                return
            msg = self.unpack_raw_message(buf)
            self.print_unpacked_message(msg)
            self.dispatch_request(msg, _sock)

    def client(self):
        """
        Client mode of the HotPlug object. Sends requests and reads responses.

        Forms request messages as Dictionaries and packs them into binary format for
        transmission. Receives response messages in binary format and unpacks them into
        Dictionaries.
        """
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
        elif (self.args.get_boot_state is True) and (self.args.cpu_list is not None):
            self.send_get_boot_state_request(msg_dict, self.args.cpu_list)
            return
        elif (self.args.get_state is True) and (self.args.cpu_list is not None):
            self.send_get_current_state_request(msg_dict, self.args.cpu_list)
            return
        elif (self.args.get_bitmasks is True):
            self.send_get_bitmasks_request(msg_dict)
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
        """Connect to the server's listening Unix domian socket.

        @param[in] sock_name - the name of the listening socket
        @returns   socket connected to the server, or throws an OSError
        """
        print("Connecting to {}".format(sock_name))
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(sock_name)
        except OSError:
            print("Error connecting to socket {}".format(sock_name))
            raise
        return self.sock

    def pack_message(self, msg_dict):
        """Packs a Dictionary containing message fields into a binary structure.

        @param[in] msg_dict - Dictionary containing message fields
        @returns   a packed structure containing the message fields
        """
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
        """Print a packed structure containing message fields.

        """
        print("{} {}", msg, len(msg))

    def print_unpacked_message(self, msg):
        """Print an unpacked Dictionary containing message fields.

        """
        print(msg)
    def write_packed_message(self, _sock, msg):
        """Write a packed structure containing message fields to a connected socket.

        @param[in] _sock - connected socket
        @param[in] msg - packed structure containing message bytes

        """
        try:
            print("sending {} bytes".format(len(msg)))
            _sock.sendall(msg)
        except OSError:
            print("Error writing packed message field to socket")

    def read_raw_message(self, _sock):
        """Read bytes from a connected socket into packed structure.

        @param[in] _sock - connected socket
        @returns   structure of  bytes containing message fields
        """
        try:
            buf = _sock.recv(288)
            print("Read {} bytes".format(len(buf)))
            return buf
        except OSError:
            print("Error reading bytes from socket")


    def unpack_raw_message(self, msg):
        """Turns a packed structure into a dictionary with message fields

        @param[in] msg - a structure containing packed bytes.
        @returns   a Dictionary containing message fields.
        """
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
        """Compare the magic number field of a message to its defined value.

        @param[in] magic - a magic number that must be the first element of any
                   hotplug message
        @returns True if the number is correct, False otherwise.
        """
        if magic == self.CONNECTION_MAGIC:
            return True
        else:
            return False

    def check_version(self, version):
        """Compare the major version of a message with the server's major version.

	@param[in] version - the major version, which defines compatibility
	@returns True if the version matches the server, False otherwise
	"""
        if version == self.PROTOCOL_VERSION:
            return True
        else:
            return False

    def dispatch_request(self, request, _sock):
        """Parses an unpacked Dictionary containing a message, dispatches it to
        the correct handler.

	@param[in] request - a Dictionary containing message elements.
        @param[in] _sock - a connected socket, which will be passed to the message handler.
	@raises ParserError NOT_HANDLED if the message is deemed to be incorrect.

        @note: this is a server method
	"""
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

        if request['action'] == self.msg_actions['GET_BOOT_STATE']:
            self.handle_get_boot_state(request, _sock)
            return

        if request['action'] == self.msg_actions['GET_CURRENT_STATE']:
            self.handle_get_current_state(request, _sock)
            return

        if request['action'] == self.msg_actions['SET_TARGET_STATE']:
            self.handle_set_target_state(request, _sock)
            return

        raise ParserError("Request message not handled", self.errors['NOT_HANDLED'])

    def client_send_rcv(self, msg_dict):
        """Client send/receive method.

	@param[in] msg_dict - a Dictionary containing message elements

        @note: Client is assumed to already have a socket connected to the server.
	"""

        msg = self.pack_message(msg_dict)
        self.write_packed_message(self.sock, msg)
        buf = self.read_raw_message(self.sock)
        response = self.unpack_raw_message(buf)
        self.print_unpacked_message(response)

    def send_unplug_request(self, msg_dict, cpu_list):
        """Sends an unplug request to the server for each CPU in the list

	@param[in] msg_dict - Dictionary containing an unplug request message
        @param[in] cpu_list - will send one message for each cpu in the list

	@note: this is a Client method
	"""
        for cpu in cpu_list:
            msg_dict['cpu'] = cpu
            msg_dict['action'] = self.msg_actions['UNPLUG']
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_unplug_request(self, msg_dict, _sock):
        """Server handler for the unplug request (above).

	@param[in] msg_dict - Dictionary containing an unplug message
        @param[in] _sock - socket connected to the client

        @note unplugs the cpu by writing to the cpu's sysfs 'online' file,
        writes a response message with the appropriate status code to the
        client socket.

	@note this is a Server method
	"""
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
        """Send a cpu plug-in request to the server.

	@param[in] msg_dict - a Dictionary containing the cpu plug request
        @param[in] cpu_list - a list of cpus for which to send this request

	@note: this is a Client method. The client must have already have a socket
        connected to the server. The client will send one request for each cpu
        in the list.
	"""
        for cpu in cpu_list:
            msg_dict['cpu'] = cpu
            msg_dict['action'] = self.msg_actions['PLUG']
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_plug_request(self, msg_dict, _sock):
        """Server handler for the plug-in request (above).

	@param[in] msg_dict - Dictionary containing a plug-in message
        @param[in] _sock - socket connected to the client

        @note plugs the cpu by writing to the cpu's sysfs 'online' file,
        writes a response message with the appropriate status code to the
        client socket.

	@note this is a Server method
	"""
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

    def send_get_boot_state_request(self, msg_dict, cpu_list):
        """Send a get boot state request to the server.

	@param[in] msg_dict - a Dictionary containing the get boot state request
        @param[in] cpu_list - a list of cpus for which to send this request

	@note: this is a Client method. The client must have already have a socket
        connected to the server. The client will send one request for each cpu
        in the list.

        @note: the boot state is not a hot-plug state, and this request is not handled
        by the Python server.
	"""
        msg_dict['action'] = self.msg_actions['GET_BOOT_STATE']
        for cpu in cpu_list:
            print("sending for cpu {}".format(cpu))
            msg_dict['cpu'] = cpu
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_get_boot_state(self, msg_dict, _sock):
        """this request is only handled by the linux kernel module"""
        print("Received a request to get the boot state of cpu {}".format(msg_dict['cpu']))
        msg_dict['msg_type'] = self.msg_types['REPLY']
        msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def send_get_current_state_request(self, msg_dict, cpu_list):
        """Send a get current state request to the server.

	@param[in] msg_dict - a Dictionary containing the get boot state request
        @param[in] cpu_list - a list of cpus for which to send this request

	@note: this is a Client method. The client must have already have a socket
        connected to the server. The client will send one request for each cpu
        in the list.

        @note: the current state a hot-plug state.
	"""
        msg_dict['action'] = self.msg_actions['GET_CURRENT_STATE']
        for cpu in cpu_list:
            print("sending for cpu {}".format(cpu))
            msg_dict['cpu'] = cpu
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_get_current_state(self, msg_dict, _sock):
        """Server handler for the get current state request (above).

	@param[in] msg_dict - Dictionary containing a plug-in message
        @param[in] _sock - socket connected to the client

        @note retrieves the current hot plug state for the cpu by reading the cpu's
        sysfs 'state' file, then writes a response message with the appropriate status
        code to the client socket.

	@note: this is a Server method
	"""
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

    def send_get_bitmasks_request(self, msg_dict):
        """Send a request forr the server to copy all four cpu bitmasks and return them.

	@param[in] msg_dict = a Dictionary containing the get_bitmasks request

        @note: there are four bitmasks: possible, present, available, and active.
               Each bitmask has a specific meaning. See below, from linux cpumask.h

        * The following particular system cpumasks and operations manage
        * possible, present, active and online cpus.
        *
        *     cpu_possible_mask- has bit 'cpu' set iff cpu is populatable
        *     cpu_present_mask - has bit 'cpu' set iff cpu is populated
        *     cpu_online_mask  - has bit 'cpu' set iff cpu available to scheduler
        *     cpu_active_mask  - has bit 'cpu' set iff cpu available to migration

        @note: returns the kernel's count of CPU IDs in the cpu field.
	"""
        msg_dict['action'] = self.msg_actions['GET_CPU_BITMASKS']
        self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_get_bitmasks_request(self, msg_dict, _sock):
        """this request is only handled by the linux kernel module"""
        print("Received a request to copy the cpu bitmasks")
        msg_dict['msg_type'] = self.msg_types['REPLY']
        msg_dict['result'] = self.errors['NOT_HANDLED']
        reply = self.pack_message(msg_dict)
        self.write_packed_message(_sock, reply)
        return

    def send_set_target_state_request(self, msg_dict, cpu_list, target):
        """Send a set target state request to the server.

	@param[in] msg_dict - a Dictionary containing the get boot state request
        @param[in] cpu_list - a list of cpus for which to send this request
        @param[in] target - the new target hot plug state for the cpu

	@note: this is a Client method. The client must have already have a socket
        connected to the server. The client will send one request for each cpu
        in the list.

        @note: a side effect of this  request will change the current hot plug state.
	"""
        msg_dict['action'] = self.msg_actions['SET_TARGET_STATE']
        msg_dict['target_state'] = target[0]
        for cpu in cpu_list:
            print("sending for cpu {}".format(cpu))
            msg_dict['cpu'] = cpu
            self.client_send_rcv(msg_dict)
        self.sock.close()
        return

    def handle_set_target_state(self, msg_dict, _sock):
        """Server handler for the set target state request (above).

	@param[in] msg_dict - Dictionary containing a plug-in message
        @param[in] _sock - socket connected to the client

        @note sets the target hot plug state for the cpu by writing to the cpu's
        sysfs 'target' file, then writes a response message with the appropriate status
        code to the client socket.

	@note: this is a Server method
        @note: a side effect of handling this request changes the current hot plug state
	"""
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
        """Reads the cpu's hotplug state file.

	@param[in] cpu - the index of the cpu
	@returns   the current hot plug state of the cpu

        @note: raises an IOError upon failure
	"""
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
        """writes to the cpu's hotplug target file.

	@param[in] cpu - the index of the cpu
	@param[in] target - the new target state
	@returns   the new target state of the cpu

        @note: raises an IOError upon failure
	"""
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


def check_args(args, parser):
    if args['listen'] == False and args['discover'] == False and args['get_boot_state'] == False and \
       args['get_state'] == False and args['plug'] == False and args['set_target'] == None and \
       args['unplug'] == False and args['get_bitmasks'] == False:
       parser.print_help()
       return False



def hotplug_main(args):
    usage_string = """usage: {} [...]""".format(sys.argv[0])
    parser = argparse.ArgumentParser(description=usage_string)
    parser.add_argument('--listen', action = 'store_true', help = 'listen for connections')
    parser.add_argument('--socket', action = 'store_true', help = 'path to domain socket')
    parser.add_argument('--discover', action = 'store_true', help = 'send a discovery request')
    parser.add_argument('--unplug', action = 'store_true', help = 'unplug one or more cpus')
    parser.add_argument('--plug', action = 'store_true', help = 'plug in one or more cpus')
    parser.add_argument('--get_boot_state', action = 'store_true', help = 'get the boot state of one or more cpus')
    parser.add_argument('--get_state', action = 'store_true', help = 'get the current state of one or more cpus')
    parser.add_argument('--get_bitmasks', action = 'store_true', help = 'get the four cpu bitmasks')
    parser.add_argument('--set_target', action = 'store', nargs = 1, type = int,
                        help = 'set the target state state for one or more cpus')
    parser.add_argument('--cpu_list', action = 'store', nargs = '*', type = int, help = 'list of one or more cpus')

    args = parser.parse_args()
    if check_args(vars(args), parser) == False:
        return

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
