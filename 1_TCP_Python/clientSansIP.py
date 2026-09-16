import socket
import struct

def checksum(data):
	# Si data est de longueur impaire
	if len(data) % 2:
		data += b"\x00"
		
	result = 0
		
	# On parcourt les éléments de data 2 par 2
	for i in range(0, len(data), 2):
		word = (data[i] << 8) + data[i+1]
		result += word
		result = (result & 0xffff) + (result >> 16)
		
	return (~result) & 0xffff
	

def segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
	pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip),0,socket.IPPROTO_TCP, 20+len(payload))
	tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5<<4, flags, 65535, 0, 0)
	tcp_checksum = checksum(pseudo_header + tcp_header + payload)
	tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5<<4, flags, 65535, tcp_checksum, 0)
	return tcp_header + payload
	
def paquet(seg):
	version = 4
	ihl = 5
	tos = 0
	total_length = 20+len(seg)
	identification = 1234
	flags = 0
	fragment_offset = 0
	ttl = 64
	protocol = socket.IPPROTO_TCP
	checksum = 0
	src_ip = "127.0.0.1"
	dst_ip = "127.0.0.1"
	ip_header = struct.pack("!BBHHHBBH4s4s", (version << 4) | ihl, tos, total_length, identification, (flags << 13) | fragment_offset,
		ttl, protocol, checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
	ip_checksum = checksum(ip_header)
	ip_header = struct.pack("!BBHHHBBH4s4s", (version << 4) | ihl, tos, total_length, identification, (flags << 13) | fragment_offset,
		ttl, protocol, ip_checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
	return ip_header + seg
	
	

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

seg = segment("127.0.0.1", "127.0.0.1", 5000,5000,1000,0,0x02, b"Hello")
paq = paquet(seg)


print(s)

s.sendto(paq, ("127.0.0.1", 0))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 5000))
rep = s.recv(1024)
print("Reponse : ", rep.decode("utf-8"))

s.close()
