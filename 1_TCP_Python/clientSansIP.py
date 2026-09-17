import socket
from structure.Segment import Segment
from structure.Packet import Packet

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

seg = Segment("127.0.0.1", "127.0.0.1", 5000,5000,1000,0,["PSH", "ACK"], b"Hello")
paq = Packet(seg.get_segment())

print(s)

s.sendto(paq.get_packet(), ("127.0.0.1", 0))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 5000))
rep = s.recv(1024)
print("Reponse : ", rep.decode("utf-8"))

s.close()
