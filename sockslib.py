#!/usr/bin/env python

import asyncore
import socket
import struct
import sys

import ringbuffer

BLOCK_SIZE = 8192

SOCKS_STATE_CLIENT_HELLO        = 1
SOCKS_STATE_WAIT_CONNECT        = 2
SOCKS_STATE_SERVER_HELLO_OPEN   = 3
SOCKS_STATE_SERVER_HELLO_CLOSE  = 4
SOCKS_STATE_RELAY               = 5
SOCKS_STATE_CLOSE               = 6

APP_STATE_CONNECTING = 1
APP_STATE_CONNECTED  = 2
APP_STATE_CLOSED     = 3

SOCKS_CLIENT_HELLO_MIN_LENGTH = 9
SOCKS_SERVER_HELLO_LENGTH = 8

SOCKS_CMD_CONNECT   = 0x01
SOCKS_CMD_BIND      = 0x02

SOCKS_REQUEST_GRANTED = 0x5a
SOCKS_REQUEST_DENIED = 0x5b

class AppClientEndpoint(asyncore.dispatcher):
    def __init__(self, host, port, socks_srv):
        print 'here'
        asyncore.dispatcher.__init__(self)
        # The data from we read from the app_server is
        # written here; the SOCKSEndpoint then reads from the
        # ringbuf when relaying to the app_client.
        self.ringbuf = ringbuffer.RingBuffer(BLOCK_SIZE * 2)
        self.socks_srv = socks_srv
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.state = APP_STATE_CONNECTING
        try:
            self.connect((host, port))
        except socket.error as e:
            self.state = APP_STATE_CLOSED
            self.close()

    def _relay_to_app_server(self):
        print 'app: relay_to_app_server'
        n = self.socks_srv.ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        if m > 0:
            data = self.socks_srv.ringbuf.peek(m)
            print 'app: relay_to_app_server: n=%d, m=%d, data="%s"' % (n, m, data)
            nsent = self.send(data)
            print 'app: relay_to_app_server: want %d, sent %d' % (m, nsent)
            if nsent:
                _ = self.socks_srv.ringbuf.read(nsent)

    def _relay_to_socks_server(self):
        print 'app: relay_to_socks_server'
        n = self.ringbuf.avail_write()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        if not data:
            return
        self.ringbuf.write(data)

    def readable(self):
        if self.state == APP_STATE_CONNECTING:
            return True
        elif self.state == APP_STATE_CONNECTED and self.ringbuf.avail_write() > 0:
            return True
        else:
            return False
    
    def writable(self):
        if self.state == APP_STATE_CONNECTING:
            return True
        elif self.state == APP_STATE_CONNECTED and self.socks_srv.ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_connect(self):
        print 'app: handle_connect'
        self.state = APP_STATE_CONNECTED

    def handle_error(self):
        print 'app: error'
        self.handle_close()

    def handle_close(self):
        print 'app: close'
        self.state = APP_STATE_CLOSED
        self.close()

    def handle_read(self):
        if self.state == APP_STATE_CONNECTED:
            self._relay_to_socks_server()

    def handle_write(self):
        if self.state == APP_STATE_CONNECTED:
            self._relay_to_app_server()


class SOCKSServerEndpoint(asyncore.dispatcher):
    def __init__(self, sock):
        asyncore.dispatcher.__init__(self, sock)
        # used for the client handshake
        self.hsbuf = bytearray()
        # data we read from app_client, headed toward the app_server
        self.ringbuf = ringbuffer.RingBuffer(BLOCK_SIZE * 2)
        self.state = SOCKS_STATE_CLIENT_HELLO
        self.socks_version = None
        self.socks_command = None
        self.user = None
        self.app = None
        self.app_port = None
        self.app_ipstr = None

    def _make_server_hello(self, status):
        self.hsbuf = struct.pack('BBHI', 0, status, 0, 0)

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

            self.state = SOCKS_STATE_WAIT_CONNECT
            self.app = AppClientEndpoint(self.app_ipstr, self.app_port, self)

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

    def _relay_to_app_server(self):
        print 'srv: relay_to_app_server'
        n = self.ringbuf.avail_write()
        m = min(BLOCK_SIZE, n)
        data = self.recv(m)
        print 'srv: relay_to_app_server: want %d, got %d' % (m, len(data))
        if not data:
            return
        self.ringbuf.write(data)

    def _relay_to_app_client(self):
        print 'srv: relay_to_app_client'
        n = self.app.ringbuf.avail_read()
        m = min(BLOCK_SIZE, n)
        data = self.app.ringbuf.peek(m)
        nsent = self.send(data)
        if nsent:
            _ = self.app.ringbuf.read(nsent)

    def readable(self):
        if self.state == SOCKS_STATE_CLIENT_HELLO:
            return True
        elif self.state == SOCKS_STATE_RELAY and self.ringbuf.avail_write() > 0:
            return True
        else:
            return False
        
    def writable(self):
        if self.state in (SOCKS_STATE_WAIT_CONNECT,
                SOCKS_STATE_SERVER_HELLO_CLOSE, SOCKS_STATE_SERVER_HELLO_OPEN):
            return True
        elif self.state == SOCKS_STATE_RELAY and self.app.ringbuf.avail_read() > 0:
            return True
        else:
            return False

    def handle_close(self):
        print 'srv: handle_close'
        asyncore.dispatcher.handle_close(self)

    def handle_read(self):
        print 'srv: handle_read'
        if self.state == SOCKS_STATE_CLIENT_HELLO:
            self._recv_client_hello()
        elif self.state == SOCKS_STATE_RELAY:
            self._relay_to_app_server()

    def handle_write(self):
        print 'srv: handle_write'
        if self.state == SOCKS_STATE_WAIT_CONNECT:
            if self.app.state == APP_STATE_CONNECTED:
                self.state = SOCKS_STATE_SERVER_HELLO_OPEN
                self._make_server_hello(SOCKS_REQUEST_GRANTED)
                self._send_server_hello_open()
            elif self.app.state == APP_STATE_CLOSED:
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
