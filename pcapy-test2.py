#!/usr/bin/env python

import pcapy
from impacket.ImpactDecoder import *
from cStringIO import StringIO
import httplib

from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

# http://stackoverflow.com/questions/2115410/does-python-have-a-module-for-parsing-http-requests-and-responses
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

promiscuous = False
max_bytes = 1024
read_timeout = 100

pc = pcapy.open_live("wlan0", max_bytes, promiscuous, read_timeout)
pc.setfilter("tcp")
pc.setfilter("dst port 80")
print "Listening on en1: net=%s, mask=%s, linktype=%d" % (pc.getnet(), pc.getmask(), pc.datalink())


def recv_pkts(hdr, data):

    eth = EthDecoder().decode(data)
    data = eth.child().child().child()

    string = data.get_packet().strip()
    if string:
        #print string
        request = HTTPRequest(string)
        print request.error_code
        print request.command
        if hasattr(request, 'path'):
            print request.path

        if hasattr(request, 'headers'):
            print request.headers

        print '----------------------------'

pc.loop(-1, recv_pkts)
