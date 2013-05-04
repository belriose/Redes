#!/usr/bin/python
# coding: utf-8

import os, sys
from datetime import datetime, timedelta
from math import log	# Para hacer logaritmo
import numpy as np	# Para el histograma y el de actividad
import matplotlib.pyplot as plt	# Para el histograma y el de actividad
from matplotlib.backends.backend_pdf import PdfPages	# Para el histograma y el de actividad
import pydot	# Para el digrafo

try: input = raw_input		# Fix python 2.x para usar input como raw_input
except NameError: pass		# Fix python 2.x para input, si estas con python 3 no hace nada

def entropia():	# Seccion principal
	# Abrir archivo de entrada
	entrada = input("Archivo de entrada: ")		# Recibo nombre del archivo de entrada donde se encuentran los datos a graficar capturados con el sniffer
	try:	# Intento abrir el archivo de entrada
		entrada = open(entrada, 'r')
	except IOError:		# Si no lo puedo abrir salgo
		print("No se pudo abrir el archivo.")
		return -1		
	lineas = [linea.strip() for linea in entrada]	# paso las lineas del archivo a una lista sacando el caracter de terminacion de linea
	if lineas[-1] == "":	# Si el ultimo elemento del archivo era una linea en blanco, lo elimino de la lista
		del lineas[-1]
		
	entrada.close()		# cierro el archivo de entrada
	titulo = input("Titulo archivos de salida: ")	# Recibo el titulo de los archivos de salida
	
	# Organizar data entrada
	sourceIP = []		# Las ips que enviaron paquetes ARP
	destIP = []			# Las ips destino en los paquetes ARP
	timestamps = []		# Los tiempos en los que se enviaron los paquetes ARP
	segundos = []		# Los tiempos en los que se enviaron en segundos, respecto al primer paquete capturado
	for linea in lineas:	# Parseo la linea del archivo de entrada y la paso a la lista correspondiente
		datos = linea.split(' ', 4);	# datos[0]: mac source   -  datos[1]: ip source  -  datos[2]: mac dst   -  datos[3]: ip dst  -  datos[4]: timestamp
		sourceIP.append(datos[1])
		destIP.append(datos[3])	
		timestamps.append(datetime.strptime(datos[4].split('.')[0],"%Y-%m-%d %H:%M:%S"))	# 2013-04-24 13:38:19 sin milisegundos
	minTime = min(timestamps)	# Me fijo el menor tiempo y lo tomo como tiempo inicial
	for stamp in timestamps:	# Construyo la lista segundos
		diferencia = stamp - minTime	# Obtengo el tiempo respecto al tiempo inicial
		segundos.append(diferencia.days * 86400 + diferencia.seconds)	# Guardo los tiempos iniciales en segundos
	del timestamps	# elimino los timestamps originales
	ips = list(set(sourceIP))		# junto las ip source sin repeticiones
	ipsDest = list(set(destIP))		# junto las ip dest sin repeticiones
	cantPaquetes = len(sourceIP)	# Cantidad de paquetes ARP enviados
	
	# ----------------------------------------------------------------
	# ---- Fuentes: ips destino --------------------------------------
	# ----------------------------------------------------------------
	probabilidadIP = []
	for ip in ipsDest:	# Para cada ip destino
		probabilidadIP.append(float(destIP.count(ip))/float(cantPaquetes))	# Calculo su probabilidad estadistica
	informacionIP = [-1 * log(p,2) if p > 0 else 0 for p in probabilidadIP]	# Calculo la informacion de las ips, i = - log(p(ip))
	probabilidadEinformacionIP = zip(probabilidadIP,informacionIP)	# Junto probabilidad e informacion en la misma lista
	probabilidadPorInformacionIP = [i[0] * i[1] for i in probabilidadEinformacionIP]	# Hago el producto probabilidad por informacion para cada ip
	entropia = sum(probabilidadPorInformacionIP)	# Sumo lo anterior y tengo la entropia
	probabilidadIP = zip(ipsDest,informacionIP)	# Junto cada ip con su probabilidad
	probabilidadIP.sort(key=lambda x: x[1])	# Los ordeno por probabilidad
	# Guardo los datos
	salida = open(titulo+"_entropia_ips_destino.txt", 'w')	# Abro el archivo de salida
	salida.write("Fuentes: ips destino\n\n")
	salida.write("Entropia de la red: "+str(entropia)+"\n\n")
	salida.write("Informacion fuentes\n")
	for dato in probabilidadIP:
		salida.write(str(dato[0])+"\t"+str(dato[1])+"\n")
	salida.close()		# Cierro el archivo de salida
	del probabilidadIP
	del informacionIP
	del probabilidadEinformacionIP
	del probabilidadPorInformacionIP
	
	# ----------------------------------------------------------------
	# ---- Fuentes: ips source ---------------------------------------
	# ----------------------------------------------------------------
	probabilidadIP = []
	for ip in ips:	# Para cada ip source
		probabilidadIP.append(float(sourceIP.count(ip))/float(cantPaquetes))	# Calculo su probabilidad estadistica
	informacionIP = [-1 * log(p,2) if p > 0 else 0 for p in probabilidadIP]	# Calculo la informacion de las ips, i = - log(p(ip))
	probabilidadEinformacionIP = zip(probabilidadIP,informacionIP)	# Junto probabilidad e informacion en la misma lista
	probabilidadPorInformacionIP = [i[0] * i[1] for i in probabilidadEinformacionIP]	# Hago el producto probabilidad por informacion para cada ip
	entropia = sum(probabilidadPorInformacionIP)	# Sumo lo anterior y tengo la entropia
	probabilidadIP = zip(ips,informacionIP)	# Junto cada ip con su probabilidad
	probabilidadIP.sort(key=lambda x: x[1])	# Los ordeno por probabilidad
	# Guardo los datos
	salida = open(titulo+"_entropia_ips_source.txt", 'w')	# Abro el archivo de salida
	salida.write("Fuentes: ips source\n\n")
	salida.write("Entropia de la red: "+str(entropia)+"\n\n")
	salida.write("Informacion fuentes\n")
	for dato in probabilidadIP:
		salida.write(str(dato[0])+"\t"+str(dato[1])+"\n")
	salida.close()		# Cierro el archivo de salida
	del probabilidadIP
	del informacionIP
	del probabilidadEinformacionIP
	del probabilidadPorInformacionIP
	
	# ----------------------------------------------------------------
	# ---- Fuentes: paquete source a destino -------------------------
	# ----------------------------------------------------------------
	enlaces = zip(sourceIP,destIP)
	fuentes = list(set(enlaces))	# las fuentes son los enlaces sin repetidos
	probabilidadEnlace = []
	for f in fuentes:	# Para cada enlace
		probabilidadEnlace.append(float(enlaces.count(f))/float(cantPaquetes))	# Calculo su probabilidad estadistica
	informacionEnlace = [-1 * log(p,2) if p > 0 else 0 for p in probabilidadEnlace]	# Calculo la informacion de las ips, i = - log(p(fuente))
	probabilidadEinformacionEnlace = zip(probabilidadEnlace,informacionEnlace)	# Junto probabilidad e informacion en la misma lista
	probabilidadPorInformacionEnlace = [i[0] * i[1] for i in probabilidadEinformacionEnlace]	# Hago el producto probabilidad por informacion para cada fuente
	entropia = sum(probabilidadPorInformacionEnlace)	# Sumo lo anterior y tengo la entropia
	probabilidadEnlace = zip(fuentes,informacionEnlace)	# Junto cada fuente con su probabilidad
	probabilidadEnlace.sort(key=lambda x: x[1])	# Los ordeno por probabilidad
	# Guardo los datos
	salida = open(titulo+"_entropia_source-destino.txt", 'w')	# Abro el archivo de salida
	salida.write("Fuentes: paquete source a destino\n\n")
	salida.write("Entropia de la red: "+str(entropia)+"\n\n")
	salida.write("Informacion fuentes\n")
	for dato in probabilidadEnlace:
		salida.write("("+str(dato[0][0])+"-"+str(dato[0][1])+")\t"+str(dato[1])+"\n")
	salida.close()		# Cierro el archivo de salida
	del probabilidadEnlace
	del informacionEnlace
	del probabilidadEinformacionEnlace
	del probabilidadPorInformacionEnlace
	
	return 1
	
	
	
	
def graficar():	# Seccion principal
	# Abrir archivo de entrada
	entrada = input("Archivo de entrada: ")		# Recibo nombre del archivo de entrada donde se encuentran los datos a graficar capturados con el sniffer
	try:	# Intento abrir el archivo de entrada
		entrada = open(entrada, 'r')
	except IOError:		# Si no lo puedo abrir salgo
		print("No se pudo abrir el archivo.")
		return -1		
	lineas = [linea.strip() for linea in entrada]	# paso las lineas del archivo a una lista sacando el caracter de terminacion de linea
	if lineas[-1] == "":	# Si el ultimo elemento del archivo era una linea en blanco, lo elimino de la lista
		del lineas[-1]
		
	entrada.close()		# cierro el archivo de entrada
	salida = input("Titulo archivos de salida: ")	# Recibo el titulo de los archivos de salida
	
	# Organizar data entrada
	sourceIP = []		# Las ips que enviaron paquetes ARP
	destIP = []			# Las ips destino en los paquetes ARP
	timestamps = []		# Los tiempos en los que se enviaron los paquetes ARP
	segundos = []		# Los tiempos en los que se enviaron en segundos, respecto al primer paquete capturado
	for linea in lineas:	# Parseo la linea del archivo de entrada y la paso a la lista correspondiente
		datos = linea.split(' ', 4);	# datos[0]: mac source   -  datos[1]: ip source  -  datos[2]: mac dst   -  datos[3]: ip dst  -  datos[4]: timestamp
		sourceIP.append(datos[1])
		destIP.append(datos[3])	
		timestamps.append(datetime.strptime(datos[4].split('.')[0],"%Y-%m-%d %H:%M:%S"))	# 2013-04-24 13:38:19 sin milisegundos
	minTime = min(timestamps)	# Me fijo el menor tiempo y lo tomo como tiempo inicial
	for stamp in timestamps:	# Construyo la lista segundos
		diferencia = stamp - minTime	# Obtengo el tiempo respecto al tiempo inicial
		segundos.append(diferencia.days * 86400 + diferencia.seconds)	# Guardo los tiempos iniciales en segundos
	del timestamps	# elimino los timestamps originales
	ips = list(set(sourceIP))		# junto las ip source sin repeticiones
	#ips = list(set(sourceIP+destIP))		# junto las ip source y las ip destination sin repeticiones
	cantIps = len(ips)	# Cantidad de ips
	ipsDest = list(set(destIP))		# junto las ip dest sin repeticiones
	cantIpsDest = len(ipsDest)	# Cantidad de ips
	
	# ----------------------------------------------------------------
	# ---- Histograma source con Matplotlib ---------------------------------
	# ----------------------------------------------------------------
	cantidadSource = []	# Cantidad de paquetes que envio la ip
	#cantidadDest = []	# Cantidad de paqueted en la que la ip fue la ip destino
	for ip in ips:		# Para todas las ips
		cantidadSource.append(sourceIP.count(ip))	# Agrego la cantidad de veces que envio ARP
		#cantidadDest.append(destIP.count(ip))	# Agrego la cantidad de veces que fue el destino
	# Crear grafico en matplotlib
	ind = np.arange(cantIps)  # Las posiciones x de las ip en el histograma
	width = 0.4		# El ancho de las barras en el histograma
	fig = plt.figure()	# Creo una nueva figura donde graficar
	ax = fig.add_subplot(111)	# Le agrego un plot a la figura
	rects1 = ax.bar(ind, cantidadSource, width, color='r')	# Agrego las barras en las posiciones x, de la cantidad de paquetes enviados, del ancho, de color rojo
	# Labels
	ax.set_title('Paquetes ARP por IP source')	# Titulo del grafico
	ax.set_ylabel('Paquetes')	# Label y
	ax.set_xticks(ind + width / 2)	# Posicion de los labels x en el grafico, en la mitad de la barra
	ax.set_xticklabels(ips)		# Lo que dicen los elementos x
	#plt.ylim([0,max(max(cantidadSource),max(cantidadDest))+1])	# Setea el rango de y de 0 al maximo +1 para que el ultimo no este en el limite
	plt.ylim([0,1.05*max(cantidadSource)+1])	# Setea el rango de y de 0 al maximo +1 para que el ultimo no este en el limite
	#ax.legend( (rects1[0], rects2[0]), ('Source', 'Destination') )	# Leyenda de cada tipo de barra

	def autolabel(rects):	# Funcion para gregar texto a las barras con la cantidad
		for rect in rects:	# Para cada barra
			height = rect.get_height()	# Obtiene la altura de la barra	
			ax.text(rect.get_x()+rect.get_width()/2., height+0.2, '%d'%int(height),
					ha='center', va='bottom')	# En la mitad de la barra, un poco arriba de la barra, el valor de la barra, ha y va no se que hacen.
	
	# Ploteo
	autolabel(rects1)	# Poner el texto a las barras
	#autolabel(rects2)	# Poner el texto a las barras
	fig.autofmt_xdate()	# Hace que el texto de los elementos x (ips) este en diagonal
	ppPdf = PdfPages(salida+'_Histograma_source.pdf')	# Inicia el archivo pdf de salida
	plt.savefig(ppPdf,format='pdf', bbox_inches='tight')	# Guarda la figura al pdf abierto, bbox_inches='tight' hace que se guarde exacto el grafico, sin margenes de mas, ni de menos
	ppPdf.close()	# Cierra el pdf
	plt.clf()		# Reset plots para que al hacer un plot nuevo este no este presente
	
	# ----------------------------------------------------------------
	# ---- Histograma destino con Matplotlib ---------------------------------
	# ----------------------------------------------------------------
	#cantidadSource = []	# Cantidad de paquetes que envio la ip
	cantidadDest = []	# Cantidad de paqueted en la que la ip fue la ip destino
	for ip in ipsDest:		# Para todas las ips
		#cantidadSource.append(sourceIP.count(ip))	# Agrego la cantidad de veces que envio ARP
		cantidadDest.append(destIP.count(ip))	# Agrego la cantidad de veces que fue el destino
	# Crear grafico en matplotlib
	ind = np.arange(cantIpsDest)  # Las posiciones x de las ip en el histograma
	width = 0.4		# El ancho de las barras en el histograma
	fig = plt.figure()	# Creo una nueva figura donde graficar
	ax = fig.add_subplot(111)	# Le agrego un plot a la figura
	rects1 = ax.bar(ind, cantidadDest, width, color='b')	# Agrego las barras en las posiciones x, de la cantidad de paquetes enviados, del ancho, de color rojo
	# Labels
	ax.set_title('Paquetes ARP por IP destino')	# Titulo del grafico
	ax.set_ylabel('Paquetes')	# Label y
	ax.set_xticks(ind + width / 2)	# Posicion de los labels x en el grafico, en la mitad de la barra
	ax.set_xticklabels(ipsDest)		# Lo que dicen los elementos x
	#plt.ylim([0,max(max(cantidadSource),max(cantidadDest))+1])	# Setea el rango de y de 0 al maximo +1 para que el ultimo no este en el limite
	plt.ylim([0,1.05*max(cantidadDest)+1])	# Setea el rango de y de 0 al maximo +1 para que el ultimo no este en el limite
	#ax.legend( (rects1[0], rects2[0]), ('Source', 'Destination') )	# Leyenda de cada tipo de barra

	def autolabel(rects):	# Funcion para gregar texto a las barras con la cantidad
		for rect in rects:	# Para cada barra
			height = rect.get_height()	# Obtiene la altura de la barra	
			ax.text(rect.get_x()+rect.get_width()/2., height+0.2, '%d'%int(height),
					ha='center', va='bottom')	# En la mitad de la barra, un poco arriba de la barra, el valor de la barra, ha y va no se que hacen.
	
	# Ploteo
	autolabel(rects1)	# Poner el texto a las barras
	#autolabel(rects2)	# Poner el texto a las barras
	fig.autofmt_xdate()	# Hace que el texto de los elementos x (ips) este en diagonal
	ppPdf = PdfPages(salida+'_Histograma_dest.pdf')	# Inicia el archivo pdf de salida
	plt.savefig(ppPdf,format='pdf', bbox_inches='tight')	# Guarda la figura al pdf abierto, bbox_inches='tight' hace que se guarde exacto el grafico, sin margenes de mas, ni de menos
	ppPdf.close()	# Cierra el pdf
	plt.clf()		# Reset plots para que al hacer un plot nuevo este no este presente
	
	# ----------------------------------------------------------------
	# ---- Actividad sources en funcion del tiempo con Matplotlib ----
	# ----------------------------------------------------------------
	ultimoSegundo = max(segundos)	# El ultimo segundo en que se capturo un paquete ARP
	indx = np.arange(ultimoSegundo)	# Las posiciones x de los segundos en el histograma
	indy = np.arange(cantIps)  # Las posiciones y de las ip en el histograma
	fig = plt.figure()	# Creo una nueva figura donde graficar
	ax = fig.add_subplot(111)	# Le agrego un plot a la figura
	# Labels
	ax.set_title('Paquetes ARP por IP source a lo largo del tiempo')	# Titulo del grafico
	ax.set_ylabel('Envio de paquetes')	# Label y
	ax.set_yticks(indy)	# Posicion de los labels y en el grafico
	ax.set_yticklabels(ips)	# Lo que dicen los labels y
	ax.set_xlabel('Tiempo (segundos)')	# Label x
	ax.grid(color='grey', linestyle='-', linewidth=0.3)	# Agrega una cuadricula gris de ancho 0.2 al grafico
	# Agregar puntos como sourceIPs
	indiceIpEnListaIp = []	# Guarda con que ip de las lista ip se corresponde cada elemento de sourceIP
	for ip in sourceIP:
		indiceIpEnListaIp.append(ips.index(ip))
	participacionesIp = list(zip(segundos, indiceIpEnListaIp))	# Junta la lista de segundos con la lista de los indices de ips en una lista de tuplas <segundo,ip>
	for punto in participacionesIp:	# Para cada elemento <segundo,ip que envio en ese segundo> agrega un punto al grafico
		plt.plot(punto[0],punto[1], color='r', marker='o')	# agrega un punto en la interseccion <segundo,ip que envio en ese segundo> de color rojo con forma o (circular)
	# Plotear
	ppPdf = PdfPages(salida+'_Actividad_sources.pdf')	# Inicia el archivo pdf de salida
	plt.savefig(ppPdf,format='pdf', bbox_inches='tight')	# Guarda la figura al pdf abierto, bbox_inches='tight' hace que se guarde exacto el grafico, sin margenes de mas, ni de menos
	ppPdf.close()	# Cierra el pdf
	plt.clf()		# Reset plots
	
	# ----------------------------------------------------------------
	# ---- Actividad dests en funcion del tiempo con Matplotlib ------
	# ----------------------------------------------------------------
	ultimoSegundo = max(segundos)	# El ultimo segundo en que se capturo un paquete ARP
	indx = np.arange(ultimoSegundo)	# Las posiciones x de los segundos en el histograma
	indy = np.arange(cantIpsDest)  # Las posiciones y de las ip en el histograma
	fig = plt.figure()	# Creo una nueva figura donde graficar
	ax = fig.add_subplot(111)	# Le agrego un plot a la figura
	# Labels
	ax.set_title('Paquetes ARP por IP destino a lo largo del tiempo')	# Titulo del grafico
	ax.set_ylabel('Envio de paquetes')	# Label y
	ax.set_yticks(indy)	# Posicion de los labels y en el grafico
	ax.set_yticklabels(ipsDest)	# Lo que dicen los labels y
	ax.set_xlabel('Tiempo (segundos)')	# Label x
	ax.grid(color='grey', linestyle='-', linewidth=0.3)	# Agrega una cuadricula gris de ancho 0.2 al grafico
	# Agregar puntos como sourceIPs
	indiceIpEnListaIp = []	# Guarda con que ip de las lista ip se corresponde cada elemento de sourceIP
	for ip in destIP:
		indiceIpEnListaIp.append(ipsDest.index(ip))
	participacionesIp = list(zip(segundos, indiceIpEnListaIp))	# Junta la lista de segundos con la lista de los indices de ips en una lista de tuplas <segundo,ip>
	for punto in participacionesIp:	# Para cada elemento <segundo,ip que envio en ese segundo> agrega un punto al grafico
		plt.plot(punto[0],punto[1], color='b', marker='o')	# agrega un punto en la interseccion <segundo,ip que envio en ese segundo> de color rojo con forma o (circular)
	# Plotear
	ppPdf = PdfPages(salida+'_Actividad_destinos.pdf')	# Inicia el archivo pdf de salida
	plt.savefig(ppPdf,format='pdf', bbox_inches='tight')	# Guarda la figura al pdf abierto, bbox_inches='tight' hace que se guarde exacto el grafico, sin margenes de mas, ni de menos
	ppPdf.close()	# Cierra el pdf
	plt.clf()		# Reset plots
	
	# ----------------------------------------------------------------
	# ---- Grafo de la topologia con pydot ---------------------------
	# ----------------------------------------------------------------
	enlaces = list(set(zip(sourceIP, destIP)))	# hago una lista de tuplas <Source ip,Destination ip> sin repetidos
	grafo = pydot.Dot(graph_type='digraph',overlap="scalexy")	# Creo un digrafo en formato dot. scalexy hace que no se solapen los nodos y que se mantenga una distancia "linda"
	for e in enlaces:
		grafo.add_edge(pydot.Edge(e[0],e[1]))	# Agrego todos los enlaces al grafo
	grafo.write_png(salida+'_topologia.png', prog='neato')	# Guardo en digrafo en un png. Neato hace que se vea "lindo" al graficarlo, en vez de en una imagen larga de estilo jerarquico
	grafo.write_png(salida+'_topologia_plain.png')	# Guardo en digrafo en un png. Neato hace que se vea "lindo" al graficarlo, en vez de en una imagen larga de estilo jerarquico

	# ----------------------------------------------------------------
	# ---- Termine de graficar ---------------------------------------
	# ----------------------------------------------------------------
	print("Listo")
	return 1
