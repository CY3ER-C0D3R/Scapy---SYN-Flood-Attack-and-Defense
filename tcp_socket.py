import scapy.all as sc
import sys

if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__

class tcp_socket(object):
    """TCP SOCKET CLASS FOR CREATING CLIENT SOCKETS DERIVED FROM A MAIN SERVER SOCKET

    Methods:
        constructor(ip, port, target_ip, target_port, seq, ack): initialize the parameters for a new client socket object
                                                                 for tcp communication (after handshake was done)
        create_tcp_pkt(): creates a new and updated tcp packet according to the parameters in the constructor
        send_pkt(fg, data): send a tcp packet to the client with option of changing flags and sending data
        recv_pkt(): sniff for one packet from the client and return the payload. If no payload return none and end
                    communication with client
        match_pkt(pkt): checks if the received packet matches the tcp sequence and acknowledgment numbers for client
        close(): close connection with client AFTER client sent FIN pkt.

    Attributes:
        ip: the client socket ip address (the server address)
        port: the client socket port (the server port)
        target_ip: the client socket target ip address (the client address)
        target_port: the client socket target port (the client port)
        seq: the client socket sequence number (can be between 0 to 4294967296)
        ack: the client socket acknowledgment number (can be between 0 to 4294967296)

    Usage:
        >> from tcp_socket import *
        >> src,sport = 192.168.1.12, 61585
        >> dst,dport = 192.168.1.16, 40115
        >> clientsocket = tcp_socket(src, sport, dst, dport, 2039668663, 2407142072)
        >> data = clientsocket.recv()
        >> print data
        'hello world'
        >> if data:
        >>     clientsocket.send_pkt('PA', data)
        >> else:
        >>     clientsocket.close()
    """
    def __init__(self, ip, port, target_ip, target_port, seq, ack):
        self.ip = ip
        self.target_ip = target_ip
        self.sport = port
        self.dport = target_port
        self.seq = seq
        self.ack = ack

    def create_tcp_pkt(self):
        """

        :return: function creates a tcp packet according to the current updated seq and ack numbers
        """
        return sc.IP(dst=self.target_ip)/sc.TCP(sport=self.sport, dport=self.dport, seq=self.seq, ack=self.ack)

    def send_pkt(self, fg='A', data=None):
        """

        :param fg: string, flags to be turned on before sending the packet
        :param data: string, data to be send as payload of the packet
        :return: function sends the packet to the client
        """
        if data:
            pkt = self.create_tcp_pkt()/data  # add the data as load to the tcp packet
            pkt[sc.TCP].flags = fg  # update the requested flags
            sc.send(pkt)
            self.seq += len(data)  # update sequence number after sending the packet
        else:
            pkt = self.create_tcp_pkt()
            pkt[sc.TCP].flags = fg
            sc.send(pkt)
            if pkt[sc.TCP].flags & 1 == 1 or pkt[sc.TCP].flags & 2 == 2:  # SYN or FIN flags are on
                self.seq += 1  # update the sequence number by one only if packet is a SYN or FIN pkt

    def recv_pkt(self):
        """

        :return: the function listens once for data from the client and returns the data if received, else returns None
        """
        pkt = sc.sniff(filter='host %s and tcp port %s' % (self.target_ip, self.dport), count=1, lfilter=lambda x: x.haslayer(sc.TCP) and self.match_pkt(x))[0]
        print pkt.summary()
        if pkt[sc.TCP].flags & 1 == 1:  # FIN flag is turned on
            return None
        if pkt.haslayer(sc.Raw):
            data = pkt.getlayer(sc.Raw).load  # data is always appears in the load part of the packet
            self.ack += len(data)  # update ack number before sending the next packet
            return data
        return None

    def match_pkt(self, pkt):
        """

        :param pkt: scapy object (class <'scapy.layers.inet'>) ; packet to check
        :return: the function check that 'PA' or 'F' flags are on and tcp sequence and acknowledgment numbers are correct.
                 Returns True or False accordingly.
        """
        return pkt[sc.TCP].ack == self.seq and pkt[sc.TCP].seq == self.ack and (pkt[sc.TCP].flags == 24 or pkt[sc.TCP].flags & 1 == 1)

    def close(self):
        """

        :return: function attempts closing the connection with the client, if some error occurs the function sends a
                 reset packet to the client to force close the connection.
        """
        fin_ack_pkt = self.create_tcp_pkt()
        fin_ack_pkt[sc.TCP].ack += 1  # update the ack number since FIN flag increments the ack by 1
        fin_ack_pkt[sc.TCP].flags = 'FA'
        ans, unans = sc.sr(fin_ack_pkt, timeout=1)  # try to recv a final ACK response from the client signifying the end of communication, wait only one second
        if not ans or not ans[0][1] or not ans[0][1].haslayer(sc.TCP) or not ans[0][1][sc.TCP].flags == 16 or ans[0][1][sc.TCP].ack != fin_ack_pkt[sc.TCP].seq+1:  # if ACK wasn't received send RST
            # reset the connection
            rst_pkt = self.create_tcp_pkt()
            rst_pkt[sc.TCP].flags = 'R'
            sc.send(rst_pkt)
        # Else: communication ended correctly
