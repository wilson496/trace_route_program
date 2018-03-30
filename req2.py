import sys
import dpkt
import socket
from statistics import mean, variance, stdev

"""
Author: Cameron Wilson
Student #: V00822184
Date submitted: March 28th, 2018
"""


class IPSession:
    # List of ip packets
    ip_list = []
    ORIGIN = ''
    ULT_DEST = ''
    offset = 0
    fragment_count = 0

    def __init__(self):
        pass

    def append(self, packet):
        self.ip_list.append(packet)

    def set_list(self, new_list):
        self.ip_list = new_list

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

    def set_offset(self, new_offset):
        self.offset = new_offset

    def get_offset(self):
        return self.offset

    def get_fragment_count(self):
        return self.fragment_count

    def inc_fragment_count(self):
        self.fragment_count += 1


def main(f):
    """This function decodes a packet capture file f and breaks it up into tcp connections"""

    # TODO: Be able to read the fragmented header. Its apparently pcap format, but the tcpdump header is invalid
    try:
        pcap = dpkt.pcapng.Reader(f)
    # except ValueError:
    #     pcap = dpkt.pcap.Reader(f)
    except Exception:
        print('Error opening pcap/pcapng file! Please ensure the file used follows either of these formats.')
        sys.exit()

    ip_sess = IPSession()

    udp_tracker = {}
    icmp_tracker = {}

    i = 0

    protocol_tracker = {}

    # Separate IP packets from traceroute file
    for ts, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        data = ip.data

        # TODO: Filter out SSDP, DP-LSP-DISC, ICMPv6
        if isinstance(ip, dpkt.ip.IP):

            try:
                dns = dpkt.dns.DNS(data.data)
                i += 1
                continue
            except:
                if isinstance(ip.data, dpkt.udp.UDP) or isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol_tracker[ip.p] = ip.get_proto(ip.p).__name__
                    ip_sess.append((ts, ip))

    # Set the origin and ultimate (final) destination for the traceroute
    ip_sess.set_origin(ip_sess.get_list()[0][1].src)
    ip_sess.set_ult_dest(ip_sess.get_list()[0][1].dst)

    # TODO: Fragmentation. Look for if the More Fragments (MF) flag is set to determine if packets have been fragmented.
    # TODO: If none of them have the MF flag, then keep the offset at 0

    # If this fires, we are dealing with Windows, so filter out the UDP
    if isinstance(ip_sess.get_list()[0][1].data, dpkt.icmp.ICMP) and ip_sess.get_list()[0][1].ttl == 1 and \
            ip_sess.get_list()[0][1].data.type == 8:
        ip_sess.set_list([packet for packet in ip_sess.get_list() if isinstance(packet[1].data, dpkt.icmp.ICMP)])



    ttl_dict = {}

    q = ip_sess.get_list()

    for ip_packet in q:

        ip = ip_packet[1]
        data = ip.data

        if ip.ttl not in ttl_dict:
            ttl_dict[ip.ttl] = 1
        else:
            ttl_dict[ip.ttl] +=1


    ttl_dict = sorted(ttl_dict.items())

    for key, value in ttl_dict:
        print("{0} : {1}".format(key, value))



if __name__ == "__main__":
    f = open(sys.argv[1], 'rb')
    main(f)


