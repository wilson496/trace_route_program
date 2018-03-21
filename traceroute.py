import sys
import dpkt
import socket

"""
Author: Cameron Wilson
Student #: V00822184
Date submitted: March 28th, 2018
"""


class IPSession:

    #List of ip packets
    ip_list = []
    ORIGIN = ''
    ULT_DEST = ''

    def __init__(self):
        pass

    def append(self, packet):
        self.ip_list.append(packet)

    def get_list(self):
        return self.ip_list

    def set_ult_dest(self, ult_dest):
        self.ULT_DEST = ult_dest

    def set_origin(self, origin):
        self.ORIGIN = origin

    def get_ult_dest(self):
        return self.ULT_DEST

    def get_origin(self):
        return self.ORIGIN

def main(f):

    """This function decodes a packet capture file f and breaks it up into tcp connections"""
    pcap = dpkt.pcapng.Reader(f)


    ip_sess = IPSession()


    #Separate IP packets from traceroute file
    for ts, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        #udp = ip.data

        if isinstance(ip, dpkt.ip.IP):
            if isinstance(ip.data, dpkt.udp.UDP) or isinstance(ip.data, dpkt.icmp.ICMP):
                ip_sess.append((ts, ip))

    #Iterate through list in IPSession and do stuffs
    ip_list = ip_sess.get_list()

    #ip_header = ip.__hdr__
    #print(ip.__hdr__)


    #Set the origin and ultimate (final) destination for the traceroute
    ip_sess.set_origin(ip_list[0][1].src)
    ip_sess.set_ult_dest(ip_list[0][1].dst)

    for packet in ip_list:
        ip = packet[1]
        udp = packet[1].data


        connection_id = (ip.src, ip.dst)
        # print(connection_id)
        #print(socket.inet_ntoa(connection_id[0]))
        #print(socket.inet_ntoa(connection_id[1]))

    print(socket.inet_ntoa(ip_sess.get_origin()))
    print(socket.inet_ntoa(ip_sess.get_ult_dest()))

if __name__ == "__main__":
    f = open(sys.argv[1], 'rb')
    main(f)


