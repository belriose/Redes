#!/usr/bin/python
# coding: utf-8

import os, sys
from scapy.all import *
from datetime import datetime, timedelta
analisis = __import__("analisis")

salida  = ''	# Archivo de salida para sniffer
timeout = timedelta(minutes=30)		# En minutos, cada cuanto hay que renovar si o si una entrada en la tabla
nodos = dict()	# Tabla arp, Nodo = [ IP, [MAC, TIMESTAMP] ]
	
def main():		# Seccion principal
	try: input = raw_input  # Fix python 2.x para usar input como raw_input
	except NameError: pass  # Fix python 2.x para input
	while True:
		printMenu()		# Imprimo el menu
		opcion = input("Opcion: ")	# Selecciono item del menu
		if opcion == "1":	# ARP: conseguir mac address de ip
			while True:
				entrada = input("Introduzca una IP (0 para salir): ")	# Entrada usuario
				if entrada == "0" :		# Salir
					break
				else:
					print(quieroMAC(entrada))	# Conseguir mac
		elif opcion == "2":
			global salida	# Declaro salida global para que sniff() pueda escribir ahi
			salida = input("Archivo de salida: ")	# Recibo nombre del archivo de salida
			salida = open(salida, 'w')	# Abro el archivo de salida
			print("Ctl + c para terminar")
			print("MAC source        IP source       MAC destination   Ip destination")
			sniff(prn=arp_monitor_callback, filter="arp", store=0)		# scapy sniff
			salida.close()		# Cierro el archivo de salida
		elif opcion == "3":
			analisis.entropia()		# Calculo la entropia de los datos capturados
		elif opcion == "4":
			analisis.graficar()		# Grafico los datos capturados
		elif opcion == "0":
			break
	return 1
	
def printMenu():
	print("**************************************")
	print("Redes - wiretapping")
	print("1. Buscar MAC address de una ip")
	print("2. Sniffear paquetes ARP")
	print("3. Calcular entropia paquetes sniffeados")
	print("4. Graficar paquetes sniffeados")
	print("0. Salir, volver atras")
	print("**************************************")
	return 1
	
# Pido la mac de una ip address
def quieroMAC(ip):
	global nodos, timeout
	if ip in nodos:	# Me fijo si la tengo guardada
		if ((datetime.now() - nodos[ip][1] ) < timeout):	# Si no expiro la sesion
			nodos[ip][1]  = datetime.now()	# Actualizo el timestamp
			return nodos[ip][0] # Devuelvo la ip
		else:	# Si expiro la sesion
			del nodos[ip]	# Elimino su entrada de la tabla
	mac = preguntarMAC(ip)	# Si no tengo guardada la ip o expiro, intento conseguirla
	if mac != -1:	# Si consegui la mac
		nodos[ip] = [mac,datetime.now()]	# La agrego a la tabla
	return mac	# Devuelvo la mac o que termino mal
	
# Pregunto a la red que MAC tiene esa ip
def preguntarMAC(ip):
	# Magia con scapy, srp1: envio el paquete arp en broadcast y acepto solo la primer respuesta, supongo que solo uno contesta, si contestan
	mensajeARP = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2)	# Mando el mensaje ARP, Ether dst= ff:ff... que es broadcast, arp psdt=ip, la ip a la que le pregunto su mac
	if hasattr(mensajeARP, 'src'):	# Si hay respuesta, si tiene el atributo src, si no hubo respuesta no lo tiene
		return mensajeARP.src	# Devuelvo la mac, tambien #mac = mensajeARP.sprintf(r"%Ether.src%")
	else:	# Si no hay respuesta
		return "No se obtuvo respuesta de esa ip."							
		
# Funcion que se aplica a los paquetes que se snffean
def arp_monitor_callback(pkt):	# Filtra los paqueres ARP recibidos
	global salida
	if ARP in pkt and pkt[ARP].op in (1,2): 								# who-has o is-at
			#print(pkt.sprintf("%ARP.hwsrc% %ARP.psrc%"))			# Devuelve los datos
			salida.write(pkt.sprintf("%ARP.hwsrc% %ARP.psrc% %ARP.hwdst% %ARP.pdst% ")+str(datetime.now())+'\n')	# Guardo los datos en una linea del archivo	MAC source, IP source, MAC dest, IP dest
			return pkt.sprintf("%ARP.hwsrc% %ARP.psrc% %ARP.hwdst% %ARP.pdst% ")		# Imprimo los datos en la consola

main()

# http://www.secdev.org/projects/scapy/build_your_own_tools.html
