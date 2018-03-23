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
    pcap = dpkt.pcapng.Reader(f)
    ip_sess = IPSession()

    udp_tracker = {}
    icmp_tracker = {}

    i = 0

    protocol_tracker = {}

    #Separate IP packets from traceroute file

    for ts, buf in pcap:
        i +=1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data


        if isinstance(ip, dpkt.ip.IP):
            if isinstance(ip.data, dpkt.udp.UDP) or isinstance(ip.data, dpkt.icmp.ICMP):
                ip_sess.append((ts, ip))
                protocol_tracker[ip.p] = ip.get_proto(ip.p).__name__


    #Set the origin and ultimate (final) destination for the traceroute
    ip_sess.set_origin(ip_sess.get_list()[0][1].src)
    ip_sess.set_ult_dest(ip_sess.get_list()[0][1].dst)

    #TODO: Fragmentation. Look for if the More Fragments (MF) flag is set to determine if packets have been fragmented.
    # If none of them have the MF flag, then keep the offset at 0

    #If this fires, we are dealing with Windows, so filter out the UDP
    if isinstance(ip_sess.get_list()[0][1].data, dpkt.icmp.ICMP) and ip_sess.get_list()[0][1].ttl == 1:
        ip_sess.set_list([packet for packet in ip_sess.get_list() if isinstance(packet[1].data, dpkt.icmp.ICMP)])
        windows(ip_sess)

    else:
        linux(ip_sess)


    # Print results of processing the traceroute file
    # print_out(ip_sess, protocol_tracker)

def windows(ip_sess):
    pass


def linux(ip_sess):
    for packet in ip_sess.get_list():
        ip = packet[1]
        data = packet[1].data

        # print(dir(ip))
        # print(ip.mf)
        # sys.exit()



        # print(ip.off)
        # TODO: Account for the ICMP not containing the ports of either source or destination. However, UDP packets do have source and destination ports

        # if isinstance(ip.data, dpkt.udp.UDP):
        #     connection_id = (ip.src, udp.sport, ip.dst, udp.dport)
        #
        # elif isinstance(ip.data, dpkt.icmp.ICMP):
        #     connection_id = (ip.src, ip.dst)

        # print(connection_id)

        # print("SOURCE: " + str(socket.inet_ntoa(connection_id[0])))
        # print("DEST: " + str(socket.inet_ntoa(connection_id[1])))




def print_out(ip_sess, protocol_tracker):

    print("The IP address of the source node: " + str(socket.inet_ntoa(ip_sess.get_origin())))
    print("The IP address of the ultimate destination node: " + str(socket.inet_ntoa(ip_sess.get_ult_dest())))

    # print('The IP addresses of the intermediate destination nodes: ')
    '''For each of the intermediate ips, print them out'''


    print('The values in the protocol field of IP headers:')

    key_list = sorted(list(protocol_tracker.keys()))
    for key in key_list:
        print("\t{0}: {1}".format(key, protocol_tracker[key]))



    print('The number of fragments created from the original datagram is: ' + str(ip_sess.get_fragment_count()))

    print('The offset of the last fragment is: ' + str(ip_sess.get_offset()))
    



    '''
    For each pairing (i.e. origin to intermediate, to final)
    find the average Round trip time 
    '''




if __name__ == "__main__":
    f = open(sys.argv[1], 'rb')
    main(f)


