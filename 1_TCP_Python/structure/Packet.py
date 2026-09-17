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