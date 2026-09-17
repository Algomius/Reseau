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

class Pseudo_header:
	def __init__(self, src_ip, dst_ip, payload):
		self.src_ip = src_ip                         # ip de la machine source
		self.dst_ip = dst_ip                         # ip de la machine destination
		self.payload = payload                       # données à envoyer au format binaire
	
	def get_pseudo_header(self):
		return struct.pack("!4s4sBBH", 
					 socket.inet_aton(self.src_ip), 
					 socket.inet_aton(self.dst_ip),
					 0,
					 socket.IPPROTO_TCP, 
					 20+len(self.payload))


class Segment:
	def __init__(self, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, payload):
		self.src_port = src_port                      # port de la source
		self.dst_port = dst_port                      # port de la destination
		self.seq_num = seq_num                        # Le numéro du premier octet de données contenu dans ce segment
		self.ack_num = ack_num                        # Le prochain octet que le récepteur attend
		offset = 5                                    # taille de l'entête TCP en blocs de 32 bits (minimum 5 -> 20 octets sans option, maximum 15 -> 60 octets)
		reserve = 0                                   # Réserve pour une utilisation future (évolution de TCP ?)
		self.offset_reserve = (offset << 4) | reserve # On combine 2 champs de 4 bits pour obtenir un octet
		self.flags = self.get_flags_value(flags)
		self.window = 512                             # combien d'octets le récepteur est encore capable d'accepter
		self.checksum = 0                             # sert à détecter les erreurs de transmission
		self.urgentP = 0                              # position de la donnée considérée comme urgente
		self.payload = payload                        # données à envoyer au format binaire
		pHeader = Pseudo_header(src_ip, dst_ip, payload)
		self.pseudo_header = pHeader.get_pseudo_header()

	def get_flags_value(self, flags):
		flag_value = 0
		for e in flags:
			if e == "CWR":                   # Congestion Window Reduced - indiquer que l'émetteur a réduit sa fenêtre de congestion
				flag_value += 128
			elif e == "ECE":                 # ECN Echo - Signaler une congestion détectée avec ECN
				flag_value += 64
			elif e == "URG":                 # Urgent - Indiquer que des données urgentes soient présentes
				flag_value += 32
			elif e == "ACK":                 # Acknowledgement - Indique qu'un segment a bien été reçu
				flag_value += 16
			elif e == "PSH":                 # Push - Demander de transmettre immédiatement les données à l'application
				flag_value += 8
			elif e == "RST":                 # Reset - Réinitialiser brutalement une connexion
				flag_value += 4	
			elif e == "SYN":                 # Synchronize - Etablir une connexion TCP
				flag_value += 2	
			elif e == "FIN":                 # Finish - Demander la fermeture de la connexion
				flag_value += 1	
		return flag_value

	def get_tcp_header(self):
		return struct.pack("!HHIIBBHHH", 
							self.src_port, 
							self.dst_port, 
							self.seq_num, 
							self.ack_num, 
							self.offset_reserve,
							self.flags, 
							self.window, 
							self.checksum, 
							self.urgentP)

	def get_segment(self):
		tcp_header = self.get_tcp_header()
		self.checksum = checksum(self.pseudo_header + tcp_header + self.payload)
		tcp_header = self.get_tcp_header()
		return tcp_header + self.payload

if __name__ == '__main__':
	msg = b"\x00" + b"\x00"
	print(checksum(msg))
	msg = b"\x00" + b"\x01"
	print(checksum(msg))
	msg = b"Coucou"
	print(checksum(msg))

	seg = Segment("127.0.0.1", "127.0.0.1", 5000,5000,1000,0,["PSH", "ACK"], b"Coucou")
	print(seg.get_segment())
	print(seg.checksum)
	print(checksum(seg.pseudo_header + seg.get_tcp_header() + seg.payload))

	print(seg.get_flags_value(["PSH", "ACK"]))