import socket
import os

#host
HOST = '192.168.1.100'

def sniffing(host, win, socket_prot):
    while 1:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
        sniffer.bind((host,0))

        #include IP header in captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if win==1:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


        #read in a single packet
        print(sniffer.recvfrom(65565))


def main(host):
    if os.name == 'nt':
        sniffing(host,1,socket.IPPROTO_IP)
    else:
        sniffing(host,0,socket.IPPROTO_ICMP)


if __name__ == '__main__':
    main(HOST)
            
