import socket
from structure.Segment import Segment

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

seg = Segment("127.0.0.1", "127.0.0.1", 5000,5000,1000,0,["PSH", "ACK"], b"Hello")

print(s)

s.sendto(seg.get_segment(), ("127.0.0.1", 5000))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 5000))
rep = s.recv(1024)
print("Reponse : ", rep.decode("utf-8"))

s.close()
