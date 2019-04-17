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
    def __init__(self, buf_size=BUF_SIZE):
        # a downstream node writes incoming data here
        self.in_ringbuf = ringbuffer.RingBuffer(buf_size)
        self.upstream_state = ENDPOINT_STATE_NEW

class MiddleNode:
    def __init__(self, out_buf_size=BUF_SIZE, in_buf_size=BUF_SIZE):
        # an downstream node writes incoming data here
        self.in_ringbuf = rinbuffer.RingBuffer(in_buf_size)
        # an upstream node writes outgoing data here
        self.out_ringbuf = ringbuffer.RingBuffer(out_buf_size)
        self.upstream_state = ENDPOINT_STATE_NEW
        self.downstream_state = ENDPOINT_STATE_NEW

class SinkNode:
    def __init__(self, host, port, buf_size=BUF_SIZE):
        # an upstream node writes outgoing data here
        self.state = ENDPOINT_STATE_NEW
        self.out_ringbuf = ringbuffer.RingBuffer(buf_size)
        self.downstream_state = ENDPOINT_STATE_NEW
        self.host = host
        self.port = port

class AppClientEndpoint(asyncore.dispatcher, SinkNode):
    def __init__(self, host, port, upstream_node):
        asyncore.dispatcher.__init__(self)
        SinkNode.__init__(self, host, port)
        self.upstream = upstream_node
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.downstream_state = ENDPOINT_STATE_CONNECTING
        try:
            self.connect((host, port))
        except socket.error as e:
            self.upstream_state = ENDPOINT_STATE_CLOSED
            self.close()

    def _relay_to_app_server(self):
        print 'app: relay_to_app_server'
        n = self.out_ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        if m > 0:
            data = self.out_ringbuf.peek(m)
            print 'app: relay_to_app_server: n=%d, m=%d, data="%s"' % (n, m, data)
            nsent = self.send(data)
            print 'app: relay_to_app_server: want %d, sent %d' % (m, nsent)
            if nsent:
                _ = self.out_ringbuf.read(nsent)

    def _relay_upstream(self):
        print 'app: _relay_upstreamr'
        n = self.upstream.in_ringbuf.avail_write()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        if not data:
            return
        self.upstream.in_ringbuf.write(data)

    def readable(self):
        if self.downstream_state == ENDPOINT_STATE_CONNECTING:
            return True
        elif self.downstream_state == ENDPOINT_STATE_CONNECTED and \
                self.upstream.in_ringbuf.avail_write() > 0:
            return True
        else:
            return False
    
    def writable(self):
        if self.downstream_state == ENDPOINT_STATE_CONNECTING:
            return True
        elif self.downstream_state == ENDPOINT_STATE_CONNECTED and \
                self.out_ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_connect(self):
        print 'app: handle_connect'
        self.downstream_state = ENDPOINT_STATE_CONNECTED

    def handle_error(self):
        print 'app: error'
        self.handle_close()

    def handle_close(self):
        print 'app: close'
        self.downstream_state = ENDPOINT_STATE_CLOSED
        self.close()

    def handle_read(self):
        if self.downstream_state == ENDPOINT_STATE_CONNECTED:
            self._relay_upstream()

    def handle_write(self):
        if self.downstream_state == ENDPOINT_STATE_CONNECTED:
            self._relay_to_app_server()


class SOCKSServerEndpoint(asyncore.dispatcher, SourceNode):
    def __init__(self, sock, downstream_class=AppClientEndpoint):
        asyncore.dispatcher.__init__(self, sock)
        SourceNode.__init__(self)
        self.downstream_class = downstream_class
        self.downstream = None
        # used for the client handshake
        self.hsbuf = bytearray()
        # data we read from app_client, headed toward the app_server
        self.out_ringbuf = ringbuffer.RingBuffer(BLOCK_SIZE * 2)
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
        print 'srv: recv_client_hello_domainname'
        data = self.recv(BLOCK_SIZE)
        print data
        if not data:
            return

        self.hsbuf += data
        domain_end = self.hsbuf.find('\x00')
        if domain_end == -1:
            return
        self.app_domain = self.hsbuf[:domain_end]
        self.state = SOCKS_STATE_WAIT_CONNECT
        self.downstream = self.downstream_class(self.app_domain, self.app_port, self)

    def _recv_client_hello(self):
        print 'srv: recv_client_hello'
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

            print 'srv: socks_version=%d' % self.socks_version
            print 'srv: socks_command=%d' % self.socks_command
            print 'srv: app_port=%d' % self.app_port
            print 'srv: ipstr=%s' % self.app_ipstr

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
                    print self.app_domain
                    self.state = SOCKS_STATE_WAIT_CONNECT
                    self.downstream = self.downstream_class(self.app_domain, self.app_port, self)
            else:
                self.state = SOCKS_STATE_WAIT_CONNECT
                self.downstream = self.downstream_class(self.app_ipstr, self.app_port, self)

    def _send_server_hello_open(self):
        print 'srv: send_server_hello_open'
        n = self.send(self.hsbuf)
        if n == len(self.hsbuf):
            self.state = SOCKS_STATE_RELAY
        self.hsbuf = self.hsbuf[n:]

    def _send_server_hello_close(self):
        print 'srv: send_server_hello_close'
        n = self.send(self.hsbuf)
        if n == len(self.hsbuf):
            self.state = SOCKS_STATE_CLOSE
            self.close()
        self.hsbuf = self.hsbuf[n:]

    def _relay_downstream(self):
        print 'srv: _relay_downstream'
        ringbuf = self.downstream.out_ringbuf
        n = ringbuf.avail_write()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        if not data:
            return
        ringbuf.write(data)

    def _relay_to_app_client(self):
        print 'srv: _relay_to_app_client'
        ringbuf = self.in_ringbuf
        n = ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        data = ringbuf.peek(m)
        nsent = self.send(data)
        if nsent:
            _ = ringbuf.read(nsent)

    def readable(self):
        if self.state in (SOCKS_STATE_CLIENT_HELLO, SOCKS_STATE_CLIENT_HELLO_DOMAINNAME):
            return True
        elif self.state == SOCKS_STATE_RELAY and self.downstream.out_ringbuf.avail_write() > 0:
            return True
        else:
            return False
        
    def writable(self):
        if self.state in (SOCKS_STATE_WAIT_CONNECT,
                SOCKS_STATE_SERVER_HELLO_CLOSE, SOCKS_STATE_SERVER_HELLO_OPEN):
            return True
        elif self.state == SOCKS_STATE_RELAY and self.in_ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_close(self):
        print 'srv: handle_close'
        asyncore.dispatcher.handle_close(self)

    def handle_read(self):
        print 'srv: handle_read (state=%d)' % self.state
        if self.state == SOCKS_STATE_CLIENT_HELLO:
            self._recv_client_hello()
        elif self.state == SOCKS_STATE_CLIENT_HELLO_DOMAINNAME:
            self._recv_client_hello_domainname()
        elif self.state == SOCKS_STATE_RELAY:
            self._relay_downstream()

    def handle_write(self):
        print 'srv: handle_write'
        if self.state == SOCKS_STATE_WAIT_CONNECT:
            if self.downstream.downstream_state == ENDPOINT_STATE_CONNECTED:
                self.state = SOCKS_STATE_SERVER_HELLO_OPEN
                self._make_server_hello(SOCKS_REQUEST_GRANTED)
                self._send_server_hello_open()
            elif self.downstream.downstream_state == ENDPOINT_STATE_CLOSED:
                self.state = SOCKS_STATE_SERVER_HELLO_CLOSE
                self._make_server_hello(SOCKS_REQUEST_DENIED)
                self._send_server_hello_close()
        elif self.state == SOCKS_STATE_RELAY:
            self._relay_to_app_client()

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
            SOCKSServerEndpoint(sock)

    def readable(self):
        return True

    def writeable(self):
        return False


if __name__ == '__main__':
    import sys
    SOCKSServer('', int(sys.argv[1]))
    asyncore.loop()
