import datetime
import pcapy
import sys

#FLAGS = gflags.FLAGS
#gflags.DEFINE_string('i', 'eth1',
                     #'The name of the interface to monitor')


def main(argv):
  # Parse flags
  #try:
    #argv = FLAGS(argv)
  #except gflags.FlagsError, e:
    #print FLAGS


  # Arguments here are:
  #   device
  #   snaplen (maximum number of bytes to capture _per_packet_)
  #   promiscious mode (1 for true)
  #   timeout (in milliseconds)
  cap = pcapy.open_live('wlan0', 100, 1, 0)
  cap.setfilter('tcp')
  cap.setfilter('dst port 80')

  print "Listening on %s: net=%s, mask=%s, linktype=%d" % ('wlan0', cap.getnet(), cap.getmask(), cap.datalink())

  # Read packets -- header contains information about the data from pcap,
  # payload is the actual packet as a string
  (header, payload) = cap.next()
  while header:
    print payload
    print ('%s: captured %d bytes, truncated to %d bytes'
           %(datetime.datetime.now(), header.getlen(), header.getcaplen()))

    (header, payload) = cap.next()


if __name__ == "__main__":
  main(sys.argv)
