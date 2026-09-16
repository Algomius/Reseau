import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print(s)

s.connect(("localhost", 5000))
s.sendall("Coucou".encode("utf-8"))
rep = s.recv(1024)
print("Reponse : ", rep.decode("utf-8"))

s.close()
