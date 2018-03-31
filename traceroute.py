import sys
import dpkt
import socket
from statistics import mean, variance, stdev, StatisticsError

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


    #TODO: Be able to read the fragmented header. Its apparently pcap format, but the tcpdump header is invalid
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

    #Separate IP packets from traceroute file
    for ts, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        data = ip.data

        #TODO: Filter out SSDP, DP-LSP-DISC, ICMPv6
        if isinstance(ip, dpkt.ip.IP):

            try:
                dns = dpkt.dns.DNS(data.data)
                i += 1
                continue
            except:
                if isinstance(ip.data, dpkt.udp.UDP) or isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol_tracker[ip.p] = ip.get_proto(ip.p).__name__
                    ip_sess.append((ts, ip))


    #Set the origin and ultimate (final) destination for the traceroute
    ip_sess.set_origin(ip_sess.get_list()[0][1].src)
    ip_sess.set_ult_dest(ip_sess.get_list()[0][1].dst)

    #TODO: Fragmentation. Look for if the More Fragments (MF) flag is set to determine if packets have been fragmented.
    #TODO: If none of them have the MF flag, then keep the offset at 0


    #If this fires, we are dealing with Windows, so filter out the UDP
    if isinstance(ip_sess.get_list()[0][1].data, dpkt.icmp.ICMP) and ip_sess.get_list()[0][1].ttl == 1 and ip_sess.get_list()[0][1].data.type == 8:
        ip_sess.set_list([packet for packet in ip_sess.get_list() if isinstance(packet[1].data, dpkt.icmp.ICMP)])
        hop_tracker = windows(ip_sess)
    else:
        hop_tracker = linux(ip_sess)


    # Print results of processing the traceroute file
    print_out(ip_sess, protocol_tracker, hop_tracker[0], hop_tracker[1])




def windows(ip_sess):

    connection_list = []
    hop_tracker = {}
    frag_list = []
    rtt = []

    for packet in ip_sess.get_list():
        ip = packet[1]
        data = packet[1].data


        #Check if there are fragments, denoted by the MF (More Fragments) bit being set
        if ip.mf == 1:
            ip_sess.inc_fragment_count()
            frag_list.append(ip)

        if ip_sess.get_fragment_count() > 0:
            #Last fragment
            #print("OFFSET: {0} | MF: {1}".format(ip.off, ip.mf))
            if ip.mf == 0:
                #ip_sess.set_offset(ip.off)
                ip_sess.set_offset(frag_list[-1].off)
                ip_sess.inc_fragment_count()
        # print(dir(data.data.seq))
        # print(data.type)
        # sys.exit()

        #Echo request
        if data.type == 8:
            connection_id = (ip.src, ip.dst, data.data.seq, ip.ttl)
            connection_list.append(connection_id)

        #Echo reply
        elif data.type == 0:
            pass

        #TTL exceeded
        elif data.type == 11:

            for each in list(set(connection_list)):
                if data.timeexceed.data.icmp.data.seq == each[2]:
                    rtt_id = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
                    hop_tracker[ip.src] = each[2]
                    rtt.append((rtt_id, packet[0] - each[-1]))


    hop_tuples = []
    for each in hop_tracker:
        hop_tuples.append((hop_tracker[each], socket.inet_ntoa(each)))

    return (sorted(hop_tuples, key=lambda x: x[0]), rtt)











def linux(ip_sess):

    connection_list = []
    hop_tracker = {}
    q = ip_sess.get_list()
    frag_list = []
    rtt = []

    for packet in q:

        ip = packet[1]
        data = packet[1].data



        #Check if there are fragments, denoted by the MF (More Fragments) bit being set
        if ip.mf == 1:
            ip_sess.inc_fragment_count()
            frag_list.append(ip)

        if ip_sess.get_fragment_count() > 0:
            #Last fragment
            #print("OFFSET: {0} | MF: {1}".format(ip.off, ip.mf))
            if ip.mf == 0:
                #ip_sess.set_offset(ip.off)
                ip_sess.set_offset(frag_list[-1].off)
                ip_sess.inc_fragment_count()


        # TODO: Account for the ICMP not containing the ports of either source or destination. However, UDP packets do have source and destination ports

        if isinstance(ip.data, dpkt.udp.UDP):
            connection_id = (ip.src, data.sport, ip.dst, data.dport, ip.ttl, packet[0])
            connection_list.append(connection_id)

        elif isinstance(ip.data, dpkt.icmp.ICMP):

            #If this field is present, then ICMP is a time exceeded packet for TTL. Otherwise, destination is unreachable
            if data.type == 11 and data.code == 0:

                source_match = ip.data.timeexceed.data.udp.sport

                #IDEA: There is a possibility that certain routers added to the list are NOT in the path to the ult dest

                #This MAY not work. TTL may be out of order for ips
                for each in list(set(connection_list)):
                    if source_match == each[1]:
                        rtt_id = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
                        hop_tracker[ip.src] = each[4]
                        rtt.append((rtt_id, packet[0] - each[-1]))


            #If the destination is unreachable, you have a ttl long enough to get to the ultimate_destination
            # BUT, the ultimate_destination is not listening on that port, thus giving the error.

            elif data.type == 3:
                # print("Destination unreachable")
                pass


    '''
    
        
        WRONG - router 12: 74.125.37.91
        router 13: 72.14.237.123
        WRONG - router 14: 209.85.250.121
        WRONG - router 15: 209.85.249.155
        router 16: 209.85.249.153


    '''

    hop_tuples = []
    for each in hop_tracker:
        hop_tuples.append((hop_tracker[each], socket.inet_ntoa(each)))

    return (sorted(hop_tuples, key=lambda x: x[0]), rtt)


'''
TODO:


RTT for Origin/UltDest packets


List the IP
address(es) of the intermediate destination node(s). If multiple intermediate destination nodes
exist, they should be ordered by their hop count to the source node in the increasing order.
BUG: Too many routers and out of order?


How many fragments were created from the original datagram? Note that 0 means no fragmentation. 
Print out the offset (in terms of bytes) of the last fragment of the fragmented IP
datagram. Note that if the datagram is not fragmented, the offset is 0.
BUG: The output for the fragmented file may not be right. Double check. 


Calculate the average and standard deviation of round trip time(s) between the source node
and the intermediate destination node (s) and the average round trip time between the source
node and the ultimate destination node. The average and standard deviation are calculated
over all fragments sent/received between the source nodes and the (intermediate/ ultimate)
destination node

- Get the stats for Source node and ultimate destination node 
'''




def print_out(ip_sess, protocol_tracker, hop_tracker, rtt_result):

    rtt_dict = {}
    rtt_mean = {}
    rtt_stdev = {}

    for each in rtt_result:

        rtt_mean[each[0][0]] = 0
        rtt_stdev[each[0][0]] = 0


        if not each[0] in rtt_dict:
            rtt_dict[each[0]] = [each[1]]
        elif each[0] in rtt_dict:
            rtt_dict[each[0]].append(each[1])



    for each in rtt_dict:

        rtt_mean[each[0]] = mean(rtt_dict[each]) * 1000

        #TODO: Fix variance bug. There is an issue where packets are not being added? or that if there is not enough data points, do not calculate variance


        # print(len(rtt_dict[each]))
        # sys.exit()
        if len(rtt_dict[each]) < 2:
            rtt_stdev[each[0]] = 0
        else:
            rtt_stdev[each[0]] = stdev(rtt_dict[each]) * 1000


    print("The IP address of the source node: " + str(socket.inet_ntoa(ip_sess.get_origin())))
    print("The IP address of the ultimate destination node: " + str(socket.inet_ntoa(ip_sess.get_ult_dest())))

    print('The IP addresses of the intermediate destination nodes: ')
    i = 0
    for each in hop_tracker:
        i += 1
        print('\trouter {0}: '.format(i) + str(each[1]) + " TTL: " + str(each[0]))

    print("")
    print('The values in the protocol field of IP headers:')

    key_list = sorted(list(protocol_tracker.keys()))
    for key in key_list:
        print("\t{0}: {1}".format(key, protocol_tracker[key]))


    print("")
    print('The number of fragments created from the original datagram is: ' + str(ip_sess.get_fragment_count()))

    print('The offset of the last fragment is: ' + str(ip_sess.get_offset()))
    

    '''
    For each pairing (i.e. origin to intermediate, to final)
    find the average Round trip time 
    '''

    for each in rtt_mean:
        print("The avg RRT between {0} and {1} is: {2} ms, the s.d. is: {3} ms".format(socket.inet_ntoa(ip_sess.get_origin()), each, rtt_mean[each], rtt_stdev[each]))



if __name__ == "__main__":
    f = open(sys.argv[1], 'rb')
    main(f)


