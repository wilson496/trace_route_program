import dpkt
import sys
import socket
import datetime

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

class TCPState:
    'Object used to track the state of TCP'

    #Dict to hold states
    state_dict = {}

    #Dict to hold complete connections
    complete_conn = {}

    def __init__(self, syn_counter, fin_counter, complete_connection, reset_connection):


        self.syn_counter = syn_counter
        self.fin_counter = fin_counter
        self.complete_connection = complete_connection
        self.reset_connection = reset_connection


    def inc_syn_count(self):
        self.syn_counter +=1

    def inc_fin_count(self):
        self.fin_counter +=1

    def get_fin(self):
        return self.fin_counter

    def set_fin(self, new_fin):
        self.fin_counter = new_fin

    def get_syn(self):
        return self.syn_counter

    def set_syn(self, new_syn):
        self.syn_counter = new_syn

    def inc_complete_conn(self):
        self.complete_connection +=1

    def get_complete_conn(self):
        return self.complete_connection

    def inc_reset_conn(self):
        self.reset_connection +=1

    def get_reset_conn(self):
        return self.reset_connection

    def get_state_str(self, connection_id):
        return self.state_dict[connection_id]

    def append(self, new_state, connection_id):
        self.state_dict[connection_id] = new_state

    def get_list(self):
        return self.state_dict

    def append_complete_conn(self, new_conn, connection_id):
        self.complete_conn[connection_id] = new_conn

    def get_complete_conn_list(self):
        return self.complete_conn


def check_state(syn, fin, rst_flag):

    state_str = ''


    if syn == 0 and fin == 0:
        state_str = 'S0F0'
    elif syn == 1 and fin == 0:
        state_str = 'S1F0'
    elif syn == 2 and fin == 0:
        state_str = 'S2F0'
    elif syn == 1 and fin == 1:
        state_str = 'S1F1'
    elif syn == 2 and fin == 1:
        state_str = 'S2F1'
    elif syn == 2 and fin == 2:
        state_str = 'S2F2'
    elif syn == 0 and fin == 1:
        state_str = 'S0F1'
    elif syn == 0 and fin == 2:
        state_str = 'S0F2'

    return state_str


def main(f):

    """This function decodes a packet capture file f and breaks it up into tcp connections"""
    pcap = dpkt.pcap.Reader(f)
    packet_counter = 0
    connection_table = {}

    # Create state machine for the tcp_file:
    # Parameters: syn_count, fin_count, complete_connection_count, reset_connection_count, state_str
    # (Default start state S0F0, no fins and not syns)
    tcp_state_machine = TCPState(0, 0, 0, 0)

    #Dict for holding the starting timestamps for connections
    starting_timestamp = {}

    #Dict to hold complete connections
    cc = {}

    packet_num = 0

    #keeps track of the number of packets sent in each connection
    packet_num_dict = {}

    #Window sizes
    win = {}

    #Dict to hold syns and fins
    syn_fin_tuple_dict = {}

    rst = {}

    rtt = {}




    for ts, buf in pcap:

        isComplete = False
        packet_counter += 1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        fin_flag = ( tcp.flags & 0x01 ) != 0
        syn_flag = ( tcp.flags & 0x02 ) != 0
        rst_flag = ( tcp.flags & 0x04 ) != 0
        psh_flag = ( tcp.flags & 0x08 ) != 0
        ack_flag = ( tcp.flags & 0x10 ) != 0

        flags = (
                    ( "A" if ack_flag else " " ) +
                    ( "P" if psh_flag else " " ) +
                    ( "R" if rst_flag else " " ) +
                    ( "S" if syn_flag else " " ) +
                    ( "F" if fin_flag else " " ) )




        connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)


        if syn_flag and not ack_flag:

        # TCP connection - dictionary
        # Key: connection_id: (source_ip_address, source_tcp_port, destination_ip_address, destination_tcp_port)
        # Value: list of tcp packets
        # Note that there are two connections, one from the client to the server and one from the server to the client.  This becomes
        # important when the connection is closed, because one side might FIN the connection well before the other side does.

            syn_fin_tuple_dict[connection_id] = [0,0]
            syn_fin_tuple_dict[connection_id][0] +=1

            syn_fin_tuple_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])] = [0,0]
            syn_fin_tuple_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])][0] +=1


            starting_timestamp[connection_id] = ts

            connection_table[connection_id] = []
            win[connection_id] = tcp.win

            packet_num_dict[connection_id] = 1


        elif rst_flag and ack_flag:

            starting_timestamp[connection_id] = ts
            rtt[connection_id] = ts
            rst[connection_id] = True
            rst[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])] = True

            if connection_id not in packet_num_dict:
                packet_num_dict[connection_id] = 1

            connection_table[connection_id] = []
            win[connection_id] = tcp.win

            if connection_id in packet_num_dict:
                packet_num_dict[connection_id] +=1


        elif syn_flag and ack_flag:


            starting_timestamp[connection_id] = ts

            syn_fin_tuple_dict[connection_id] = [0,0]
            syn_fin_tuple_dict[connection_id][0] +=1

            syn_fin_tuple_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])] = [0,0]
            syn_fin_tuple_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])][0] +=1

            connection_table[connection_id] = []
            win[connection_id] = tcp.win
            packet_num_dict[connection_id] = 1

        elif not syn_flag and ack_flag:

            if fin_flag:

                syn_fin_tuple_dict[connection_id][1] +=1

                syn_fin_tuple_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])][1] +=1


            if connection_id not in connection_table.keys():
                # Not a complete connection
                connection_table[connection_id] = []
                win[connection_id] = tcp.win
                packet_num_dict[connection_id] = 1

            connection_table[connection_id].append(tcp.data)

            packet_num_dict[(connection_id[2], connection_id[3], connection_id[0], connection_id[1])] +=1

        state = check_state(syn_fin_tuple_dict[connection_id][0], syn_fin_tuple_dict[connection_id][1], rst_flag)
        tcp_state_machine.append(state, connection_id)


        '''Check if there is a complete connection - evaluated after checking flags'''

        if syn_fin_tuple_dict[connection_id][0] > 0 and syn_fin_tuple_dict[connection_id][1] > 0:

            tcp_state_machine.inc_complete_conn()

            final_ts = datetime.datetime.utcfromtimestamp(ts)
            begin_ts = datetime.datetime.utcfromtimestamp(starting_timestamp[connection_id])
            duration = (final_ts - begin_ts).total_seconds()
            cc[connection_id] = [begin_ts, final_ts, duration]

            isComplete = True

            syn_fin_tuple_dict[connection_id][0] = 0
            syn_fin_tuple_dict[connection_id][1] = 0


    #calculate reset connections
    rst_cn = 0
    for each in rst:
        if rst[each] == True:
            rst_cn +=1
        if rst[each] == True and each in cc:
            tcp_state_machine.append((tcp_state_machine.get_state_str(each) + '+R'), each)


    f.close()


    print_out(str(len(connection_table)), tcp_state_machine.get_complete_conn(), rst_cn, connection_table, cc, tcp_state_machine.get_list(), packet_num_dict, win, rtt)


def print_out(total_connections, complete_connections, reset_connections, connection_table, cc, state_dict, packet_num_dict, win, rtt):

    print('A) Total number of connections: ' + total_connections)
    print('\n-------------------------------------------------------\n')


    print('B) Connections\' details:\n')

    connection_num = 1
    for conn_tuple, key, state in zip(connection_table, connection_table.keys(), state_dict):


        print("Connection: " + str(connection_num))
        print("Source Address: " + str(socket.inet_ntoa(conn_tuple[0])))
        print("Destination Address: " + str(socket.inet_ntoa(conn_tuple[2])))
        print("Source Port: " + str(conn_tuple[1]))
        print("Destination Port: " + str(conn_tuple[3]))
        print("Status: " + str(state_dict[conn_tuple]))

        #Only if the connection is complete provide the following information
        if conn_tuple in cc:

            src = conn_tuple[0]
            src_port = conn_tuple[1]
            dest = conn_tuple[2]
            dest_port = conn_tuple[3]

            src_packet_count = packet_num_dict[(src, src_port, dest, dest_port)]
            dest_packet_count = packet_num_dict[(dest, dest_port, src, src_port)]
            total_packet_count = src_packet_count + dest_packet_count



            #Take the length of EACH ITEM in connection_table for data bytes
            src_data = 0
            for each in connection_table[(src, src_port, dest, dest_port)]:
                src_data += len(each)

            dest_data = 0
            for each in connection_table[(dest, dest_port, src, src_port)]:
                dest_data += len(each)

            total_data = src_data + dest_data

            print("Start time: " + str(cc[conn_tuple][0]))
            print("End Time: " + str(cc[conn_tuple][1]))
            print("Duration: " + str(cc[conn_tuple][2]))
            print("Number of packets sent from Source to Destination: " + str(src_packet_count))
            print("Number of packets sent from Destination to Source: " + str(dest_packet_count))
            print("Total number of packets: " + str(total_packet_count))
            print("Number of data bytes sent from Source to Destination: " + str(src_data))
            print("Number of data bytes sent from Destination to Source: " + str(dest_data))
            print("Total number of data bytes: " + str(total_data))

        print("\nEND\n")
        print("+++++++++++++++++++++++++++++++++")
        print(".")
        print(".")
        print(".")
        print("+++++++++++++++++++++++++++++++++\n")
        connection_num +=1

    print("\n")
    print('C) General\n')
    print('Total number of complete TCP connections: ' + str(complete_connections))
    print('Number of reset TCP connections: ' + str(reset_connections))
    print("Number of TCP connections that were still open when the trace capture ended: "+ str(len(connection_table) - complete_connections))


    print("\n")


    #For each complete connection, calculate this stuff
    print("D) Complete TCP connections: ")
    print("\n")


    # Keys for minimum and Maximum connection durations
    min_key = min(cc.keys(), key=(lambda k: cc[k]))
    max_key = max(cc.keys(), key=(lambda k: cc[k]))

    sum_ = []
    for each in cc:
        sum_.append(cc[each][-1])
        mean = sum(sum_) / len(cc)


    print("Minimum time duration: " + str(cc[max_key][2]))


    # due to issues with types, the min key gave max value and max key gave min value
    print("Mean time duration: " + str(mean))
    print("Maximum time duration: " + str(cc[min_key][2]))
    print("\n")

    complete_conn_pn_dict = {}
    for each in packet_num_dict:
        if each in cc:
            complete_conn_pn_dict[each] = (packet_num_dict[each] + packet_num_dict[(each[2], each[3], each[0], each[1])])

    min_key = min(complete_conn_pn_dict.keys(), key=(lambda k: complete_conn_pn_dict[k]))
    max_key = max(complete_conn_pn_dict.keys(), key=(lambda k: complete_conn_pn_dict[k]))

    sum_ = []
    for each in complete_conn_pn_dict:
        sum_.append(complete_conn_pn_dict[each])
    mean = sum(sum_) / len(complete_conn_pn_dict)

    print("Minimum number of packets including both send/received: " + str(complete_conn_pn_dict[min_key]))
    print("Mean number of packets including both send/received: " + str(mean))
    print("Maximum number of packets including both send/received: "+ str(complete_conn_pn_dict[max_key]))
    print("\n")

    complete_win = {}
    for each in win:
        if each in cc:
            complete_win[each] = (win[each] + win[(each[2], each[3], each[0], each[1])])

    min_key = min(complete_win.keys(), key=(lambda k: complete_win[k]))
    max_key = max(complete_win.keys(), key=(lambda k: complete_win[k]))

    sum_ = []
    for each in complete_win:
        sum_.append(complete_win[each])
    mean = sum(sum_) / len(complete_win)


    print("Minimum receive window size including both send/received: " + str(complete_win[min_key]))
    print("Mean receive window size including both send/received: " + str(mean))
    print("Maximum receive window size including both send/received: " + str(complete_win[max_key]))


if __name__ == "__main__" :
    f = open(sys.argv[1], 'rb')
    main(f)
