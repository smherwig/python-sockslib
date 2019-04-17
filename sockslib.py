#!/usr/bin/env python

import asyncore
import socket
import struct
import sys

import ringbuffer

BLOCK_SIZE = 8192
BUF_SIZE = 8192

SOCKS_STATE_CLIENT_HELLO            = 1
SOCKS_STATE_CLIENT_HELLO_DOMAINNAME = 2
SOCKS_STATE_WAIT_CONNECT            = 3
SOCKS_STATE_SERVER_HELLO_OPEN       = 4
SOCKS_STATE_SERVER_HELLO_CLOSE      = 5
SOCKS_STATE_RELAY                   = 6
SOCKS_STATE_CLOSE                   = 7

ENDPOINT_STATE_NEW        = 1
ENDPOINT_STATE_CONNECTING = 2
ENDPOINT_STATE_CONNECTED  = 3
ENDPOINT_STATE_CLOSED     = 4

SOCKS_CLIENT_HELLO_MIN_LENGTH = 9
SOCKS_SERVER_HELLO_LENGTH = 8

SOCKS_CMD_CONNECT   = 0x01
SOCKS_CMD_BIND      = 0x02

SOCKS_REQUEST_GRANTED = 0x5a
SOCKS_REQUEST_DENIED = 0x5b

# outbound (out) means data going from application client to application server
#
# inbound  (in) means data going from application server to application client
#
# upstream means closer to the application client
#
# downstream means closer to the application server


class SourceNode:
    def __init__(self, downstream_class, buf_size=BUF_SIZE):
        self._downstream_class = downstream_class
        # a downstream node writes incoming data here
        self._in_ringbuf = ringbuffer.RingBuffer(buf_size)
        self._upstream_state = ENDPOINT_STATE_NEW

    def avail_write_up(self):
        return self._in_ringbuf.avail_write()

    def write_up(self, data):
        return self._in_ringbuf.write(data)

    def get_upstream_state(self):
        return self._upstream_state

class MiddleNode:
    def __init__(self, host, port, upstream, downstream_class, out_buf_size=BUF_SIZE,
            in_buf_size=BUF_SIZE):
        self._host = host
        self._port = port
        # an downstream node writes incoming data here
        self._in_ringbuf = ringbuffer.RingBuffer(in_buf_size)
        # an upstream node writes outgoing data here
        self._out_ringbuf = ringbuffer.RingBuffer(out_buf_size)
        self._upstream = upstream
        self._downstream = downstream_class(host, port, self)

    def avail_write_up(self):
        return self._upstream.avail_write_up()

    def write_up(self, data):
        return self._upstream.write_up(data)

    def avail_write_down(self):
        return self._downstream.avail_write_down()

    def write_down(self, data):
        return self._downstream.write_down(data)
    
    def get_upstream_state(self):
        return self._upstream.get_upstream_state()

    def get_downstream_state(self):
        return self._downstream.get_downstream_state()


class SinkNode:
    def __init__(self, host, port, upstream, buf_size=BUF_SIZE):
        # an upstream node writes outgoing data here
        self._host = host
        self._port = port
        self._upstream = upstream
        self._out_ringbuf = ringbuffer.RingBuffer(buf_size)
        self._state = ENDPOINT_STATE_NEW

    def avail_write_down(self):
        return self._out_ringbuf.avail_write()

    def write_down(self, data):
        return self._out_ringbuf.write(data)

    def get_downstream_state(self):
        return self._state


class AppClientEndpoint(asyncore.dispatcher, SinkNode):
    def __init__(self, host, port, upstream):
        asyncore.dispatcher.__init__(self)
        SinkNode.__init__(self, host, port, upstream)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self._state = ENDPOINT_STATE_CONNECTING
        try:
            self.connect((host, port))
        except socket.error as e:
            self._state = ENDPOINT_STATE_CLOSED
            self.close()

    def _relay_to_app_server(self):
        n = self._out_ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        if m > 0:
            data = self._out_ringbuf.peek(m)
            nsent = self.send(data)
            if nsent:
                _ = self._out_ringbuf.read(nsent)

    def _relay_upstream(self):
        n = self._upstream.avail_write_up()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        if not data:
            return
        self._upstream.write_up(data)

    def readable(self):
        if self._state == ENDPOINT_STATE_CONNECTING:
            return True
        elif self._state == ENDPOINT_STATE_CONNECTED and \
                self._upstream.avail_write_up() > 0:
            return True
        else:
            return False
    
    def writable(self):
        if self._state == ENDPOINT_STATE_CONNECTING:
            return True
        elif self._state == ENDPOINT_STATE_CONNECTED and \
                self._out_ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_connect(self):
        self._state = ENDPOINT_STATE_CONNECTED

    def handle_error(self):
        self.handle_close()

    def handle_close(self):
        self._state = ENDPOINT_STATE_CLOSED
        self.close()

    def handle_read(self):
        if self._state == ENDPOINT_STATE_CONNECTED:
            self._relay_upstream()

    def handle_write(self):
        if self._state == ENDPOINT_STATE_CONNECTED:
            self._relay_to_app_server()


class SOCKSServerEndpoint(asyncore.dispatcher, SourceNode):
    def __init__(self, sock, downstream_class=AppClientEndpoint):
        asyncore.dispatcher.__init__(self, sock)
        SourceNode.__init__(self, downstream_class)
        self._downstream = None
        # used for the client handshake
        self.hsbuf = bytearray()
        # data we read from app_client, headed toward the app_server
        self.state = SOCKS_STATE_CLIENT_HELLO
        self.socks_version = None
        self.socks_command = None
        self.user = None
        self.app_port = None
        self.app_ipstr = None
        self.app_domain = None

    def _make_server_hello(self, status):
        self.hsbuf = struct.pack('BBHI', 0, status, 0, 0)

    def _recv_client_hello_domainname(self):
        data = self.recv(BLOCK_SIZE)
        if not data:
            return

        self.hsbuf += data
        domain_end = self.hsbuf.find('\x00')
        if domain_end == -1:
            return
        self.app_domain = self.hsbuf[:domain_end]
        self.state = SOCKS_STATE_WAIT_CONNECT
        self._downstream = self._downstream_class(self.app_domain, self.app_port, self)

    def _recv_client_hello(self):
        data = self.recv(BLOCK_SIZE)
        if not data:
            return
        self.hsbuf += data
        if len(self.hsbuf) >= SOCKS_CLIENT_HELLO_MIN_LENGTH:
            user_end = self.hsbuf.find('\x00', SOCKS_CLIENT_HELLO_MIN_LENGTH - 1)
            if user_end == -1:
                return
            self.socks_version, self.socks_command, self.app_port, \
                    self.app_ipstr = struct.unpack('>BBH4s', self.hsbuf[:8])
            self.user = self.hsbuf[8:user_end]
            self.app_ipstr = socket.inet_ntoa(self.app_ipstr)

            if self.socks_version != 4:
                print 'error'
                # TODO: error
                pass

            if self.app_ipstr.startswith('0.0.0.'):
                self.hsbuf = self.hsbuf[user_end+1:]
                domain_end = self.hsbuf.find('\x00')
                if domain_end == -1:
                    self.state = SOCKS_STATE_CLIENT_HELLO_DOMAINNAME
                    return
                else:
                    self.app_domain = str(self.hsbuf[:domain_end])
                    self.state = SOCKS_STATE_WAIT_CONNECT
                    self._downstream = self._downstream_class(self.app_domain, self.app_port, self)
            else:
                self.state = SOCKS_STATE_WAIT_CONNECT
                self._downstream = self._downstream_class(self.app_ipstr, self.app_port, self)

    def _send_server_hello_open(self):
        n = self.send(self.hsbuf)
        if n == len(self.hsbuf):
            self.state = SOCKS_STATE_RELAY
        self.hsbuf = self.hsbuf[n:]

    def _send_server_hello_close(self):
        n = self.send(self.hsbuf)
        if n == len(self.hsbuf):
            self.state = SOCKS_STATE_CLOSE
            self.close()
        self.hsbuf = self.hsbuf[n:]

    def _relay_downstream(self):
        n = self._downstream.avail_write_down()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        if not data:
            return
        self._downstream.write_down(data)

    def _relay_to_app_client(self):
        n = self._in_ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        data = self._in_ringbuf.peek(m)
        nsent = self.send(data)
        if nsent:
            _ = self._in_ringbuf.read(nsent)

    def readable(self):
        if self.state in (SOCKS_STATE_CLIENT_HELLO, SOCKS_STATE_CLIENT_HELLO_DOMAINNAME):
            return True
        elif self.state == SOCKS_STATE_RELAY and self._downstream.avail_write_down() > 0:
            return True
        else:
            return False
        
    def writable(self):
        if self.state in (SOCKS_STATE_WAIT_CONNECT,
                SOCKS_STATE_SERVER_HELLO_CLOSE, SOCKS_STATE_SERVER_HELLO_OPEN):
            return True
        elif self.state == SOCKS_STATE_RELAY and self._in_ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_close(self):
        asyncore.dispatcher.handle_close(self)

    def handle_read(self):
        if self.state == SOCKS_STATE_CLIENT_HELLO:
            self._recv_client_hello()
        elif self.state == SOCKS_STATE_CLIENT_HELLO_DOMAINNAME:
            self._recv_client_hello_domainname()
        elif self.state == SOCKS_STATE_RELAY:
            self._relay_downstream()

    def handle_write(self):
        if self.state == SOCKS_STATE_WAIT_CONNECT:
            if self._downstream.get_downstream_state() == ENDPOINT_STATE_CONNECTED:
                self.state = SOCKS_STATE_SERVER_HELLO_OPEN
                self._make_server_hello(SOCKS_REQUEST_GRANTED)
                self._send_server_hello_open()
            elif self._downstream.get_downstream_state() == ENDPOINT_STATE_CLOSED:
                self.state = SOCKS_STATE_SERVER_HELLO_CLOSE
                self._make_server_hello(SOCKS_REQUEST_DENIED)
                self._send_server_hello_close()
        elif self.state == SOCKS_STATE_RELAY:
            self._relay_to_app_client()


# XXX: for example purposes:
class ToUpperResponse(MiddleNode):
    def __init__(self, host, port, upstream, downstream_class=AppClientEndpoint):
        MiddleNode.__init__(self, host, port, upstream, downstream_class)

    def write_up(self, data):
        return self._upstream.write_up(data.upper())

class SOCKSServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print 'listener: Incoming connection from %s' % repr(addr)
            #SOCKSServerEndpoint(sock, ToUpperResponse)
            SOCKSServerEndpoint(sock)

    def readable(self):
        return True

    def writeable(self):
        return False


if __name__ == '__main__':
    import sys
    SOCKSServer('', int(sys.argv[1]))
    asyncore.loop()
