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
		self.window = 65535                           # combien d'octets le récepteur est encore capable d'accepter
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
	
class Packet:
	def __init__(self, segment):
		version = 4                                            # Indique la version du protocole IP (4 pour IPV4)
		ihl = 5                                                # Longueur de l'entête en mots de 32 bits (val min 5 -> 20 octets)
		self.version_ihl = (version << 4) | ihl
		self.typeOfService = 0                                 # caractéristiques de service souhaitées (priorité, délai, débit)
		self.total_length = 20+len(segment)                    # Longueur du datagramme IP en octets
		self.identification = 1234                             # identifiant utiliser pour le réassemblage du même datagramme
		flags = 0                                              # Contrôle de fragmentation
		fragment_offset = 0                                    # position du fragment dans le datagramme original
		self.flags_offset = (flags << 13) | fragment_offset    
		self.timeToLive = 64                                   # Limite le nombre de sauts qu'un paquet peut effectuer 
		self.protocol = socket.IPPROTO_TCP                     # Identifie le protocole transporté par IP (TCP : 6, UDP : 17)
		self.checksum = 0                                      # sert à détecter les erreurs de transmission
		self.src_ip = "127.0.0.1"                              # adresse IPv4 de l'émetteur
		self.dst_ip = "127.0.0.1"                              # adresse IPv4 du destinataire
		self.segment=segment

	def get_ip_header(self):
		return 	struct.pack("!BBHHHBBH4s4s", 
					  self.version_ihl,
					  self.typeOfService, 
					  self.total_length, 
					  self.identification, 
					  self.flags_offset,
					  self.timeToLive, 
					  self.protocol, 
					  self.ip_checksum, 
					  socket.inet_aton(self.src_ip), 
					  socket.inet_aton(self.dst_ip))

	def get_packet(self):
		ip_header = self.get_ip_header()
		self.checksum = checksum(ip_header)
		ip_header = self.get_ip_header()
		return ip_header + self.segment

class Frame:
	def __init__(self, packet):
		self.src_mac = bytes.fromhex("00 00 00 00 00 00")
		self.dst_mac = bytes.fromhex("00 00 00 00 00 00")
		self.etherType = 0x0800
		self.packet = packet

	def get_ethernet_header(self):
		return struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.etherType)

	def get_frame(self):
		return self.get_ethernet_header() + self.packet


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
