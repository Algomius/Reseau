import struct

class Frame:
	def __init__(self, packet):
		self.src_mac = bytes.fromhex("00 00 00 00 00 00")                   # Adresse mac source
		self.dst_mac = bytes.fromhex("00 00 00 00 00 00")	                # Adresse mac destination
		self.etherType = 0x0800                                             # Identification du protocole transporté (0x0800 : Internet protocol version 4 (IPv4)) 
		self.packet = packet                                                # Paquet IP à encapsuler

	def get_ethernet_header(self):
		return struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.etherType)

	def get_frame(self):
		return self.get_ethernet_header() + self.packet
