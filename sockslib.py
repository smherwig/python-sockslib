#!/usr/bin/env python

import binascii
import errno
import getopt
import select
import socket
import struct
import sys

import event
import ringbuffer
import socketutils

"""
all big endian

SOCKS 4
=======
client -> server
    u8  version  [0x4]
    u8  command  [0x01] = connect, [0x02] = bind
    u16 port
    u32 ip
    var id      user id, terminated with 0x00 

server -> client
    u8  unused  [0x00]
    u8  status  0x5a = request granded, 0x5b = request reject or failed
    u16 unused
    u32 unused

SOCKS 4a
========
SOCKS 5
=======
    RFC1928, RFC1929
"""

STATE_COMMAND = 1
STATE_RELAY = 2

CMD_SIZE = 9
BUF_SIZE = 1024

CMD_CONNECT = 0x01
CMD_BIND = 0x02

STATUS_REQUEST_GRANTED = 0x5a

#########################################
# SOCKS Connection
#
#
#  src --- sockserve -->  dst
#########################################
STATE_HANDSHAKE = 1
STATE_SOURCE_CLOSE = 1

SOCKS_HANDSHAKE_MIN_SIZE = 9


def log_debug(fmt, *args):
    ffmt = '[debug] %s' % fmt
    line = ffmt % args
    if not line.endswith('\n'):
        line += '\n'
    sys.stderr.write(line)


# XXX: you can probably just do a socks4, and not worry about socks5
class SOCKSConnection:
    def __init__(self, sock, event_loop):
        self.s_sock = sock
        self.s_sock.setblocking(0)
        self.event_loop = event_loop
        self.state = STATE_HANDSHAKE
        self.version  = None
        self.cmd = None
        self.d_sock = None
        self.d_ipstr = None
        self.d_port = None  
        self.handshake_buf = bytearray()
        # TODO: rename to outgoing and incoming, respectively.
        self.s2d_buf = ringbuffer.RingBuffer(16348)
        self.d2s_buf = ringbuffer.RingBuffer(16348)
        # TODO: abstract the writes to the outgoing ringbuffer
        # and the reads from the incoming ringbuffer, so that a module
        # can override (perhaps by providing their own buffering).
        # we'll start out with just the default nul module that just
        # passes the data straight through:  that is, the _s_recv should
        # look something like:
        #
        #
        #   data = self.s_sock_recv(n)
        #   # handle errors and closure
        #   data = module.on_recv(data)
        #   self.outgoing.write(data)
        #
        # simliarly the other send/recv functions

    def _s_handshake(self):
        n = len(self.handshake_buf)
        data = self.s_sock.recv(SOCKS_HANDSHAKE_MIN_SIZE - n)
        if not data:
            self.state = STATE_SOURCE_CLOSE
            return
        self.handshake_buf += data

        if len(self.handshake_buf) == SOCKS_HANDSHAKE_MIN_SIZE:
            self.version, self.cmd, self.port, ip, self.user = \
                    struct.unpack('>BBH4sB', self.handshake_buf)

            self.d_ipstr = socket.inet_ntoa(ip)
            log_debug('SOCKS handshake: version=%d, cmd=%02x, dst=%s:%d, user=%s' % \
                    (self.version, self.cmd, self.d_ipstr, self.d_port, self.user)

            self.d_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.d_sock.setblocking(0)
            self.event_loop.add(self.d_sock, EVENT_READ | EVENT_WRITE, 
                self.handle_dst)

            self.event_loop.modify(self.s_sock, EVENT_READ, EVENT_WRITE, 
                self.handle_src) 
            self.state = STATE_RELAY

    def _s_recv(self):
        try:
            n = min(self.s2d_buf.avail_write(), 8192)
            data = self.s_sock.recv(n)
        except socket.error as e:
            if e.errno != errno.EAGAIN
                self.state = STATE_ERROR
        if not data:
            self.state = STATE_SOURCE_CLOSE
        else:
            self.s2d_buf.write(data)

    def _s_send(self):
        n = min(self.d2s_buf.avail_read(), 8192)
        data = self.d2s_buf.peek(n)
        try:
            m = self.s_sock.send(data)
        except socket.error as e:
            if e.errno != errno.EAGAIN
                self.state = STATE_ERROR
        if m > 0:
            _ = self.d2s_buf.read(m)

    def s_handle(self, revent):
        if self.state == STATE_HANDSHAKE:
            self._do_handshake()
        if self.state == STATE_RELAY:
            self._do_relay()

        if self.state == STATE_SOURCE_CLOSE or self.state == STATE_ERROR:
            # TODO: destroy client
            return

        # TODO: reschedule in event_loop      

    def _d_recv(self):
        try:
            n = min(self.d2s_buf.avail_write(), 8192)
            data = self.s_sock.recv(n)
        except socket.error as e:
            if e.errno != errno.EAGAIN
                self.state = STATE_ERROR
        if not data:
            self.state = STATE_SOURCE_CLOSE
        else:
            self.d2s_buf.write(data)

    def _d_send(self):
        n = min(self.s2d_buf.avail_read(), 8192)
        data = self.s2d_buf.peek(n)
        try:
            m = self.s_sock.send(data)
        except socket.error as e:
            if e.errno != errno.EAGAIN
                self.state = STATE_ERROR
        if m > 0:
            _ = self.s2d_buf.read(m)

    def d_handle(self, revent):
        if revent = EVENT_READ:
            data = self.d_sock.recv(1024)

        elif revent == EVENT_WRITE:
            
            pass


def SOCKSServer:
    def __init__(self, port, event_loop):
        self.sock = socketutils.tcp4server(port, blocking=False)
        self.event_loop = event_loop

    def serve(self):
        c, ai = self.sock.accept()
        log_debug('new connection from %s:%d' % ai)
        conn = SOCKSConnection(c)
        self.event_loop.add(c, EVENT_READ, conn.handle_src)

def main(argv):
    port = int(argv[1])
    event_loop = event.EventLoop()
    server = SOCKSServer(port, event_loop)
    event_loop.add(server.sock, event.EVENT_READ, server.serve)
    event_loop.loop()


if __name__ == '__main__':
    main(sys.argv)
