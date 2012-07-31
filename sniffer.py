#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Copyright (C) 2011  h4ckinger
    Contact	: contact@h4ckinger.org
    Web		: www.h4ckinger.org

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

#------------imports------------#
from threading import Thread
from time import sleep
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from cStringIO import StringIO
import re, urlparse, gzip
try:
	import pcapy
except ImportError:
	print "Install python-pcapy and WinPcap(Windows) / libpcap(Linux)"
	exit()





class PacketLoop(Thread):
	""" PacketLoop(Thread) Main Class """
	def __init__(self, pcapy_object):
		""" PacketLoop(Thread) Class Constructor """
		datalink = pcapy_object.datalink()
		if pcapy.DLT_EN10MB == datalink:
			self.decoder = EthDecoder()
		elif pcapy.DLT_LINUX_SLL == datalink:
			self.decoder = LinuxSLLDecoder()
		else:
			print "Datalink type not supported: " % datalink
			exit()
		self.pcap	=	pcapy_object
		Thread.__init__(self)
		self.stop	= False
	#----------------------------------------------------------------------
	def run(self):
		""" Thread Main Function """
		while not self.stop:
			self.pcap.dispatch(1, self.packet_handler)
	#----------------------------------------------------------------------
	def get_ips(self, decoded_data):
		""" Returns src and dst ips in tuple format """
		return (decoded_data.child().get_ip_src(), decoded_data.child().get_ip_dst())
	#----------------------------------------------------------------------
	def get_ports(self, decoded_data):
		""" Returns src and dst ports in tuple format """
		return (
		        decoded_data.child().child().get_th_sport(),
		        decoded_data.child().child().get_th_dport()
			)
	#----------------------------------------------------------------------
	def get_raw_data(self, decoded_data):
		""" Returns byte data """
		#return decoded_data.child().child().child().get_buffer_as_string()
		return decoded_data.child().child().child().get_packet()

	#----------------------------------------------------------------------
	def packet_handler(self, header, data):
                print data
                import sys
                sys.exit(12)
		"""
		Packet Handler Function
		Use the ImpactDecoder to turn the rawpacket into a human readable format
		"""
		decoded_data		= self.decoder.decode(data)
		src_ip,	dst_ip		= self.get_ips(decoded_data)
		src_port, dst_port	= self.get_ports(decoded_data)
		raw_data		= self.get_raw_data(decoded_data)
		#print "[%s:%s] --> [%s:%s]" % (src_ip, src_port, dst_ip, dst_port)

                print raw_data

		if raw_data.startswith("HTTP"):
			decode_raw	= HttpResponseDecoder(raw_data)
			decode_raw.parse()
			print decode_raw
			print decode_raw.body
			self.stop	= True
		else:
			decode_raw	= HttpRequestDecoder(raw_data)
			decode_raw.parse()
			print decode_raw


class HttpMessageDecoder:
	"""  HttpMessageDecoderMain Class """
	def __init__(self, raw_data):
		"""  HttpMessageDecoder Class Constructor """
		self.raw_data	= raw_data
		self.field_line		= re.compile(r'\s*(?P<key>.+\S)\s*:\s+(?P<value>.+\S)\s*')
		self.first_line_end	= None #int position
		self.headers_end	= None #int position
		self._headers		= None #dict header items
		self.raw_headers	= None #string raw headers
		self._rawbody		= None #raw body
		self.info_line		= None #first line (infos)
	#----------------------------------------------------------------------
	def parse_headers(self):
		""" Parse raw headers and raw body"""
		clrf			= "\r\n"
		self.first_line_end	= self.raw_data.find(clrf)
		self.headers_end	= self.raw_data.find(clrf * 2)

		self.info_line		= self.raw_data[:self.first_line_end]
		self.raw_headers	= self.raw_data[self.first_line_end + len(clrf) : self.headers_end]
		self._rawbody		= self.raw_data[self.headers_end + len (clrf * 2):]
		l_headers		= [
						(key.lower(), value) for key, value in
		                                self.field_line.findall(self.raw_headers)
					]
		self._headers = dict(l_headers)


	#----------------------------------------------------------------------
	@property
	def headers(self):
		""" property headers getter """
		return self._headers
	#----------------------------------------------------------------------
	def get_header(self, name):
		""" Return value of given header """
		return self._headers.get(name,"None")



class HttpRequestDecoder(HttpMessageDecoder):
	""" HttpRequestDecoder Main Class """
	def __init__(self, raw_data):
		""" HttpRequestDecoder Class Constructor """
		self.raw_data	= raw_data
		HttpMessageDecoder.__init__(self, raw_data)
		self.req_line	= re.compile(r'(?P<method>GET|POST|HEAD)\s+(?P<resource>.+?)\s+(?P<version>HTTP/1.(1|0))')
		self._info	= None
	#----------------------------------------------------------------------
	def parse(self):
		""" parse headers, request, body """
		self.parse_headers()
		self._info = self.req_line.match(self.info_line).groupdict()
		self.parse_url()
	#----------------------------------------------------------------------
	def parse_url(self):
		""" url parser function """
		return urlparse.urlparse(self.url)._asdict()
	#----------------------------------------------------------------------
	@property
	def method(self):
		""" method property """
		return self._info.get("method")

	#----------------------------------------------------------------------
	@property
	def url(self):
		""" property url """
		return "http://%s%s" % (self.get_header("host"), self._info.get("resource"))

	@property
	def body(self):
		""" property body getter """
		#TODO: Eger raw body de post parametreleri varsa burada ayikla
		return self._rawbody or "No Body"
	#----------------------------------------------------------------------
	def __str__(self):
		""" Printable """
		return "[%s] - %s" % (self.method, self.parse_url()["path"])


class HttpResponseDecoder(HttpMessageDecoder):
	""" HttpResponseDecoder Main Class """
	def __init__(self, raw_data):
		""" HttpResponseDecoder Class Constructor """
		self.raw_data	= raw_data
		HttpMessageDecoder.__init__(self, raw_data)
		self.resp_line	= re.compile(r'(?P<version>HTTP/1.(1|0))\s+(?P<code>[0-9]{3})\s+(?P<msg>.*?)$')
		self._info	= None
	#----------------------------------------------------------------------
	def parse(self):
		""" parse headers, request, body """
		self.parse_headers()
		self._info	= self.resp_line.match(self.info_line).groupdict()
	#----------------------------------------------------------------------
	def is_gzipped(self):
		"""
		Returns True if raw_body compressed via gzip
		else returns False
		"""
		return self.get_header("content-encoding") == "gzip"

	#----------------------------------------------------------------------
	@property
	def code(self):
		""" property http code """
		return self._info.get("code","None")
	#----------------------------------------------------------------------
	@property
	def msg(self):
		""" property http message """
		return self._info.get("msg","None")
	#----------------------------------------------------------------------
	@property
	def version(self):
		""" property http version """
		return self._info.get("version","None")

	#----------------------------------------------------------------------
	@property
	def body(self):
		"""
		property body getter
		Returns plain text body even if body is compressed by gzip
		"""
		return self._rawbody
		if not self.is_gzipped():
			return self._rawbody
		else:
			io_body	= StringIO(self._rawbody)
			gzipper	= gzip.GzipFile(fileobj = io_body)
			return gzipper.read()
	#----------------------------------------------------------------------
	def __str__(self):
		""" Printable """
		return "[%s %s - %s]" % (self.version, self.code, self.msg)


class Sniffer:
	""" Sniffer Main Class """
	def __init__(self):
		""" Sniffer Class Constructor
		GET,POST,HEADER and HTTP filter
		"""
		self.pcapy_filter	= 'port 80 and (\
		                        tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or \
		                        tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 or \
		                        tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450 or \
		                        tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x484541444552\
		                        )'
		self.pcapy		= None
		self.interface		= "wlan0"
		#self.interface		= r"\\Device\\NPF_{1080C748-9F0E-4E6F-A723-9CF4FCAC8B6E}"

	#----------------------------------------------------------------------
	def start_sniff(self):
		""" Starts pcapy """
		try:
			dt	= PacketLoop(self.pcapy)
			dt.setDaemon(True)
			dt.start()
			while dt.isAlive():
				sleep(0.3)
		except (KeyboardInterrupt, SystemExit):
			dt.stop	= False
			print "[-] Aborted"
			exit()
	#----------------------------------------------------------------------
	def check_if_root(self):
		""" Checks if script running with root privleges """
		compare	= 0
		try:
			#try if OS is Linux
			from os import getuid as is_root
		except ImportError:
			#if catch exception OS should be Windows
			import ctypes
			is_root	= ctypes.windll.shell32.IsUserAnAdmin
			compare	= 1

		return is_root() == compare
	#----------------------------------------------------------------------
	def build_pcapy(self):
		""" Preparing pcapy object """
		self.pcapy	= pcapy.open_live(self.interface, 10000, 0, 2000)
		self.pcapy.setfilter( self.pcapy_filter)
	#----------------------------------------------------------------------
	def get_interface(self):
		""" List All Interfaces """
		return pcapy.findalldevs()
	#----------------------------------------------------------------------
	def main(self):
		""" Class Main """
		if not self.check_if_root():
			print "Script only runs with root privleges "
			exit()

		#print self.get_interface()

		self.build_pcapy()
		self.start_sniff()




if __name__ == "__main__":
	sniffer	=	Sniffer()
	sniffer.main()
