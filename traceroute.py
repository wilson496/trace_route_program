import sys
import dpkt


"""
Author: Cameron Wilson
Student #: V00822184
Date submitted: March 5th, 2018
"""


'''
SOURCE:
https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp.py#L10

This source was used to help with using tuples as keys to manage state information for the different connections 
'''


def main(f):

    """This function decodes a packet capture file f and breaks it up into tcp connections"""
    pcap = dpkt.pcapng.Reader(f)
    packet_counter = 0

    for ts, buf in pcap:
        print(ts, buf)






if __name__ == "__main__" :
    f = open(sys.argv[1], 'rb')
    main(f)
