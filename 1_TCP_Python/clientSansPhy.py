import socket
from structure.Segment import Segment
from structure.Packet import Packet
from structure.Frame import Frame

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

seg = Segment("127.0.0.1", "127.0.0.1", 5000,5000,1000,0,["SYN"], b"Hello")
paq = Packet(seg.get_segment())
tra = Frame(paq.get_packet())

print(s)

s.sendto(tra.get_frame(), ("lo", 0))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 5000))
rep = s.recv(1024)
print("Reponse : ", rep.decode("utf-8"))

s.close()
