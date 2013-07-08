# -*- coding: utf-8 -*- 
# # # # # # # # # # # # # # # # # # # # #
#									   #									   
#	Trabajo Práctico 3 - Conexiones	# 
#									   #
#	 Teoría de las Comunicaciones	  #
#	  Departamento de Computación	  #
#			  FCEN - UBA			   #
#			junio de 2013			  #
#									   #
# # # # # # # # # # # # # # # # # # # # #


import threading
import random

from common import PacketBuilder, ProtocolControlBlock
from soquete import Soquete
from packet import ACKFlag, FINFlag, SYNFlag
from worker import ClientProtocolWorker
from buffers import DataBuffer, RetransmissionQueue, NotEnoughDataException
from constants import MIN_PACKET_SIZE, MAX_PACKET_SIZE, CLOSED,\
					  ESTABLISHED, FIN_SENT, SYN_SENT, MAX_SEQ,\
					  SEND_WINDOW, MAX_RETRANSMISSION_ATTEMPTS


class ClientControlBlock(ProtocolControlBlock):
	
	def __init__(self, address, port):
		ProtocolControlBlock.__init__(self, address, port)
		# Próximo SEQ a enviar
		self.send_seq = random.randint(1, MAX_SEQ)
		# Tamaño de la ventana de emisión
		self.send_window = SEND_WINDOW
		# Límite inferior de la ventana (i.e., unacknowledged)
		self.window_lo = self.send_seq
		# Límite superior de la ventana
		self.window_hi = self.modular_sum(self.window_lo, self.send_window)
		#~ self.window_hi = self.window_lo + self.send_window	# Por que no hacer la suma asi?
		
	def get_send_seq(self):
		return self.send_seq
	
	def get_send_window(self):
		return self.send_window
	
	#############################
	### Completar esta clase! ###
	#############################
	
	# Responde True sii la ventana de emisión no está saturada.
	def send_allowed(self):
		#~ print "Seq:",self.send_seq," window_lo:",self.window_lo," window_hi:",self.window_hi
		#~ print "Send allowed:",self.send_seq < self.window_hi
		return self.send_seq < self.window_hi

	def increment_send_seq(self):
		#~ print "Prev seq:",self.send_seq
		self.send_seq += 1
		#~ print "Inc seq:",self.send_seq
		
	def valid_ack(self,ack):
		return self.window_lo <= ack and ack <= self.send_seq
	
	def update_window(self,ack):
		self.window_hi += (ack - self.window_lo) + 1
		self.window_lo += (ack - self.window_lo) + 1
		
	def get_window_lo(self):
		return self.window_lo

class PTCClientProtocol(object):
	
	def __init__(self, address, port):
		self.retransmission_queue = RetransmissionQueue(self)
		self.retransmission_attempts = dict()
		self.outgoing_buffer = DataBuffer()
		self.state = CLOSED
		self.control_block = ClientControlBlock(address, port)
		self.socket = Soquete(address, port)
		self.packet_builder = PacketBuilder(self)
	
	def is_connected(self):
		return self.state == ESTABLISHED
		
	def build_packet(self, payload=None, flags=None):
		seq = self.control_block.get_send_seq()
		if payload is not None:
			self.control_block.increment_send_seq()
		packet = self.packet_builder.build(payload=payload, flags=flags, seq=seq)
		return packet
		
	def send_packet(self, packet):
		self.socket.send(packet)
		
	def send_and_queue_packet(self, packet):
		self.send_packet(packet)
		self.retransmission_queue.put(packet)
		
	def send(self, data):
		if not self.is_connected():
			raise Exception('cannot send data: connection not established')
		self.worker.send(data)

	def connect_to(self, address, port):
		self.worker = ClientProtocolWorker.spawn_for(self)
		self.worker.start()
		self.connected_event = threading.Event()
		self.control_block.set_destination_address(address)		# No tendria que ser el protocol block ?
		self.control_block.set_destination_port(port)		# No tendria que ser el protocol block ?
		
		syn_packet = self.build_packet(flags=[SYNFlag])
		self.send_and_queue_packet(syn_packet)
		self.state = SYN_SENT
		
		self.connected_event.wait()
	
	def handle_timeout(self):
		###################
		##   Completar!  ##
		###################
		
		# Tener en cuenta que se debe:
		# (1) Obtener los paquetes en self.retranmission_queue
		# (2) Volver a enviarlos
		# (3) Reencolarlos para otra eventual retransmisión
		# ...y verificar que no se exceda la cantidad máxima de reenvíos!
		# (hacer self.shutdown() si esto ocurre y dejar un mensaje en self.error)
		haypaquetesret = len(self.retransmission_queue.packets()) > 0
		if haypaquetesret:
			print "Retransmit"
			self.retransmission_queue.__iter__()
			primer_paquete = self.retransmission_queue.next().get_seq_number()
			if self.retransmission_attempts.get(primer_paquete,0) >= MAX_RETRANSMISSION_ATTEMPTS:
				self.error = "Error muchas retransmisiones"
				self.shutdown()
			else:
				copia_retransmission_queue = self.retransmission_queue.packets()
				self.retransmission_queue.clear()
				for pack in copia_retransmission_queue:
					self.send_and_queue_packet(pack)
					self.retransmission_attempts[pack.get_seq_number()] = self.retransmission_attempts.get(pack.get_seq_number(),0) + 1	# Le sumo uno a su cantidad de retransmisiones, inicilizandolo en cero si no existe
	
	def handle_pending_data(self):
		more_data_pending = False
		
		if self.control_block.send_allowed():
			try:
				data = self.outgoing_buffer.get(MIN_PACKET_SIZE, MAX_PACKET_SIZE)
			except NotEnoughDataException:
				pass
			else:
				packet = self.build_packet(payload=data)
				self.send_and_queue_packet(packet)
				
			if not self.outgoing_buffer.empty():
				more_data_pending = True
		else:
			more_data_pending = True
		
		if more_data_pending:
			self.worker.signal_pending_data()
	
	def handle_incoming(self, packet):
		###################
		##   Completar!  ##
		###################
		
		# Tener en cuenta que se debe:
		# * Corroborar que el flag de ACK esté seteado
		# * Distinguir el caso donde el estado es SYN_SENT
		#   * No olvidar de hacer self.connected_event.set() al confirmar el ACK y establecer la conexión!!!
		# * Analizar si #ACK es aceptado (hablar con el bloque de control para hacer este checkeo)
		# * Sacar de la cola de retransmisión los paquetes reconocidos por #ACK
		# * Ajustar la ventana deslizante con #ACK
		# * Tener en cuenta también el caso donde el estado es FIN_SENT
		ack_num = packet.get_ack_number()
		if ACKFlag in packet and self.control_block.valid_ack(ack_num):	# si hay ack y es valido
			self.retransmission_queue.acknowledge(packet)	# lo sacamos del retransmission queue
			self.control_block.update_window(ack_num)	# actualizamos la ventana
			for packs_ack in range(self.control_block.get_window_lo(),ack_num+1):	# Eliminamos los paquetes ackeados del diccionario de intentos de retransmision
				del retransmission_attempts[packs_ack]
			
			if self.state == SYN_SENT:	# Si estaba desconectado, conectate
				self.state = ESTABLISHED
				self.connected_event.set()
			elif self.state == FIN_SENT:	# Si te reconoce el fin de la conexion, terminala
				self.state = CLOSED
				self.retransmission_queue.clear()
				self.retransmission_attempts.clear()
				self.close()
			#~ if self.outgoing_buffer and self.retransmission_queue.empty():	#  Si recibimos el ack de lo ultimo imprimimos cuanto tardo
				#~ print clock() - start_time
			
	def handle_close_connection(self):
		if not self.outgoing_buffer.empty():
			self.worker.signal_pending_data()
			self.worker.signal_close_connection()
		elif not self.retransmission_queue.empty():
			self.worker.signal_close_connection()
		else:
			fin_packet = self.build_packet(flags=[FINFlag])
			self.send_and_queue_packet(fin_packet)
			self.state = FIN_SENT
		
	def close(self):
		if self.is_connected():
			self.worker.signal_close_connection()
		
	def shutdown(self):
		self.outgoing_buffer.clear()
		self.retransmission_queue.clear()
		self.retransmission_attempts.clear()
		self.worker.stop()
		# Esto es por si falló el establecimiento de conexión (para destrabar al thread principal)
		self.connected_event.set()
		self.state = CLOSED
