import socket as s
import traceback

HOST='192.168.1.160'
PORT=61585
BUFSIZE = 1024
ADRR = (HOST,PORT)
tcpCliSock = s.socket(s.AF_INET,s.SOCK_STREAM)
tcpCliSock.connect(ADRR)

print 'Client Side'
while True:
    data = raw_input("> ")
    if not data: break
    tcpCliSock.send(data)
    data=tcpCliSock.recv(BUFSIZE)
    if not data: break
    try:
        data=eval(data)
        for d in data:
            print d
            if d.startswith('SERVER IS CHANGING TO PORT:'):
                PORT = d.split()[-1]  # get new port
                tcpCliSock.close()
                ADRR = (HOST,int(PORT))
                tcpCliSock = s.socket(s.AF_INET,s.SOCK_STREAM)
                tcpCliSock.connect(ADRR)
                print 'Client changed port successfully'
    except:
        print traceback.format_exc()
        print 'invalid syntax'
tcpCliSock.close()
