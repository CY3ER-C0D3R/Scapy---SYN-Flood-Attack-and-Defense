import sys
import socket
import scapy.all as sc
from tcp_socket import *
import random
import thread

connected_clients = []  # saves the clients that are connected
in_connect = {}  # saves the clients that are being accepted {(ip,port):[num_of_sent_syns, (seq,ack)]}
PORT = 0
current_thread = 0  # handles the open threads after changing ports

def get_open_ports():
    '''

    :return: first open port number
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

def listen(ip, port, thread_number):
    """
    
    :param ip: server ip 
    :param port: server port
    :return: function listens for important new connections (SYN and ACK for tcp handshake)
    """
    global current_thread

    sc.sniff(filter='host %s and tcp port %s' % (ip, port),
             lfilter=lambda pkt: pkt.haslayer(sc.TCP) and (pkt[sc.TCP].flags == 2 or pkt[sc.TCP].flags == 16) and not is_malicious_client((pkt[sc.IP].src, pkt[sc.TCP].sport)) and current_thread == thread_number,
             prn=lambda x: accept(x))

def accept(pkt):
    """
    
    :param pkt: gets a tcp packet with SYN or ACK flags turned on 
    :return: updates the connection status for the client and if three-way-handshake finished adds a new socketobj to connected_clients
    """
    global in_connect, PORT, connected_clients

    addr = (pkt.getlayer(sc.IP).src, pkt.getlayer(sc.TCP).sport)  # client address
    if pkt[sc.TCP].flags & 2 == 2:  # if pkt is SYN
        in_connect[addr] = [in_connect[addr][0] + 1 if addr in in_connect else 1, (0, 0)]  # update number of SYN requests for client
        if in_connect[addr][0] > 2:  # if more than 2 SYN requests from one client treat as attacker
            handle_attacker(addr)
        else:  # not attacker
            # pick a new random seq number and update the ack number
            seq = random.randrange(0, 2**32)
            ack = pkt[sc.TCP].seq+1
            in_connect[addr][1] = (seq, ack)  # save seq and ack for future checking
            print 'currently in connect: ', in_connect
            sc.send(sc.IP(dst=addr[0])/sc.TCP(sport=PORT, dport=addr[1], seq=seq, ack=ack, flags='SA'))  # send SYN-ACK pkt to client
    elif pkt[sc.TCP].flags & 16 == 16:  # if pkt is ACK
        if addr in in_connect and in_connect[addr][1] == (pkt[sc.TCP].ack-1, pkt[sc.TCP].seq):  # if packet matches tcp handshake
            clientsocket = tcp_socket(pkt[sc.IP].dst, pkt[sc.TCP].dport, addr[0], addr[1], in_connect[addr][1][0]+1, in_connect[addr][1][1])
            print '...connected from ', addr
            del in_connect[addr]  # client finished connection process
            connected_clients.append(clientsocket)
            thread.start_new_thread(handle_client, (clientsocket, addr))

def handle_client(clientsock, addr):
    """
    
    :param clientsock: client object 
    :param addr: client addr - (ip,port)
    :return: function handles communication with the client
    """
    global connected_clients, PORT

    while True:
        data = clientsock.recv_pkt()
        if not data:
            break
        if clientsock.sport != PORT:  # if server changed port inform client and renew connection
            msg = "['SERVER IS CHANGING TO PORT: %s'," % PORT + "'...echoed: " + data + "']"
            clientsock.send_pkt('PA', msg)
            break
        msg = "['...echoed: " + data + "']"
        clientsock.send_pkt('PA', msg)
    clientsock.close()
    del connected_clients[connected_clients.index(clientsock)]  # delete client from connected clients
    print 'client', addr, 'disconnected...'

def handle_attacker(addr):
    """
    
    :param addr: attacker's address (ip,port) 
    :return: handles the attack
    """
    global PORT

    print 'Attacked by', addr
    # send malicious client RST
    sc.send(sc.IP(src='172.16.15.140', dst=addr[0])/sc.TCP(sport=PORT, dport=addr[1], flags='R'))
    # update malicious address to black-list file
    update_to_file('black-list', 0, addr[0], addr[1])
    # change port and update to file
    current_port = PORT
    while current_port == PORT:  # find a new port
        PORT = get_open_ports()
    update_to_file('Server Info', 1, '172.16.15.140', PORT)

def create_data_file(name, opt):
    """
    :param name: name (str) of the file to create
    :param opt: option (int) how to create the file
    :return: the function opens a file and saves ip,port either for server or for black-list
    """
    if opt == 1:  # server ip,port file
        f = open(name, "wb")
        f.write("IP: \n")
        f.write("PORT: ")
        f.close()
    else:  # black-list file
        f = open(name, "wb")
        f.close()

def update_to_file(name, opt, ip=None, port=None):
    """
    
    :param name: file name 
    :param opt: 1 or other, for difference between the two files
    :param ip: str, ip of malicious client or server according to opt
    :param port: int, port of malicious client or server according to opt
    :return: updates the matching file with the parameters
    """
    name = name+ ".txt"
    try:
        f = open(name, "rb+") if opt == 1 else open(name, "ab")
    except IOError:  # if file doesn't exist create file
        create_data_file(name, opt)
        f = open(name, "rb+") if opt == 1 else open(name, "ab")
    if f:
        if opt == 1:  # server ip,port file
            lines = f.readlines()
            f.seek(0)
            f.truncate()
            for line in lines:
                if "IP: " in line:
                    f.write("IP: "+str(ip))
                    f.write("\n")
                elif "PORT: " in line:
                    f.write("PORT: "+str(port))
                    f.write("\n")
                else:
                    f.write(line)
                    f.write("\n")
        else:  # add malicious client to black-list
            if ip and port:
                f.write("('"+str(ip)+"',"+str(port)+")")
                f.write("\n")
        f.close()
    else:
        print "File not found"

def get_from_file(name, opt):
    """
    
    :param name: file name 
    :param opt: option - 1 or else. 
    :return: if server file returns server address, else returns list of malicious clients
    """
    name = name+".txt"
    try:
        f = open(name, "rb")  # read only
    except Exception as e:
        print e
        return None
    lines = f.readlines()
    if opt != 1:  # return all malicious client addresses
        return lines
    ip = None
    port = None
    for line in lines:
        if "IP: " in line:
            ip = line.split()[1]
        elif "PORT: " in line:
            port = line.split()[1]
    f.close()
    return ip, port  # return server address

def is_malicious_client(addr):
    """
    
    :param addr: (ip,port) of client 
    :return: if client is in the malicious clients list (on file)
    """
    malicious_clients = get_from_file('black-list', 0)
    for m_client in malicious_clients:
        m_client = eval(m_client.split("\n")[0])
        if m_client == addr:
            return True
    return False

def main():
    global PORT, connected_clients, in_connect, current_thread

    if sys.stdout != sys.__stdout__:
        sys.stdout = sys.__stdout__

    myHost = "172.16.15.140"  # default server ip address, can be changed
    myPort = 49368 #get_open_ports()  # server main port
    PORT = myPort

    # create the following files if they do not exist or update them if they already exist
    update_to_file('Server Info', 1, myHost, myPort)
    update_to_file('black-list', 0)

    print 'waiting for connection...'
    thread.start_new_thread(listen, (myHost, myPort, current_thread))

    while True:
        if myPort != PORT:
            myPort = PORT
            print 'SERVER CHANGING PORT TO: ', myPort
            # update to file
            update_to_file('Server Info', 1, myHost, myPort)
            while True:
                if not connected_clients:
                    print 'listening on new port now'
                    break
            in_connect = {}
            current_thread += 1
            thread.start_new_thread(listen, (myHost, myPort, current_thread))

if __name__ == '__main__':
    main()
