#!/usr/bin/env python

import pcapy
from impacket.ImpactDecoder import *
from cStringIO import StringIO
import httplib
import gzip

from BaseHTTPServer import BaseHTTPRequestHandler
from httplib import HTTPResponse
from StringIO import StringIO

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

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

class Capture(object):
    promiscuous = False
    max_bytes = 1024*10
    read_timeout = 100

    request = None
    request_string = None
    response = None
    response_string = None

    def __init__(self):
        pc = pcapy.open_live("wlan0", self.max_bytes, self.promiscuous, self.read_timeout)
        pc.setfilter("tcp")
        pc.setfilter("dst port 80 or src port 80")
        print "Listening on eth0: net=%s, mask=%s, linktype=%d" % (pc.getnet(), pc.getmask(), pc.datalink())
        pc.loop(-1, self.recv_pkts)

    def recv_pkts(self, hdr, data):

        eth = EthDecoder().decode(data)
        data = eth.child().child().child()

        # http://www.httpwatch.com/httpgallery/chunked/

        string = data.get_packet()

        # print string
        # print '---------------'
        # return

        if string:
            print 'binnen'

            if string.startswith('HTTP'): #begin of a new response
                print 'nieuwe response'
                self.response_string = string
                self.response = self.make_response(self.response_string)

            elif string.split("\n")[0].find('HTTP/') > 0: #begin of a new request
                if self.response:
                    self.request.response = self.response
                    # print self.request.rfile.read()
                    # print string

                    if self.request.response.getheader('Content-Encoding') == 'gzip':
                        buf = StringIO(self.request.response.read())
                        f = gzip.GzipFile(fileobj=buf)
                        print f.read()
                    else:
                        pass
                        # print self.request.response.read()

                    # print self.request.response.getheaders()

                    self.response = None #unset old response
                    self.response_string = None

                print 'nieuwe request'
                self.request_string = string
                self.request = self.make_request(self.request_string)
            else:
                if self.response_string:
                    print 'toevoegen aan response'
                    self.response_string = self.response_string + string
                    self.response = self.make_response(self.response_string)
                elif self.request_string:
                    print 'toevoegen aan request'
                    self.request_string = self.request_string + string
                    self.request = self.make_request(self.request_string)

    def make_request(self, string):
        return HTTPRequest(string)

    def make_response(self, string):
        socket = FakeSocket(StringIO(string).read())
        response = HTTPResponse(socket)
        response.begin()
        return response

Capture()
