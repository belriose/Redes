#!/usr/local/bin/python
# coding: utf-8

import os, sys, string
from math import radians, cos, sin, asin, sqrt
from scapy.all import IP, ICMP, sr1, scapy
from time import time, sleep
from datetime import datetime, timedelta
if sys.version_info[0] >= 3:	# Si la version de python >= 3 importo estas librerias
	import urllib.request as request
	import json
else:	# Para versiones 2 de python importo estas
	import urllib2 as request
	import simplejson as json	#	https://pypi.python.org/pypi/simplejson/

tiempoPropagacion = 200	# Km / milisegundo
	
# Ping con default timeout 10 por defecto.
def ping(ip,timeToLive=64,imprimir=1,tOut=10):	# imprimir = 1 hace que salga por consola los avisos
	if imprimir == 1:
		print("Pingueando",ip)
	echorequest = IP(dst=ip,ttl=timeToLive)/ICMP()	# Armo el paquete del ping
	tiempoInicio = datetime.now()
	echoreply = sr1(echorequest,timeout=tOut,verbose=0)		# Envio y espero a recibir el paquete, verbose hace que no imprima todo por consola
	tiempoFinal = datetime.now()
	rtt = (tiempoFinal - tiempoInicio)
	rtt = (rtt.days *  86400000 + rtt.seconds * 1000 + rtt.microseconds / 1000 ) 	# rtt en milisegundos
	if imprimir == 1:
		if type(echoreply) is scapy.layers.inet.IP:		# Si hubo respuesta
			#echoreply.show()
			print("Respondio",ip,"en",str(rtt),"milisegundos")
		else:	# Si hubo timeout
			print("Request timeout")
	return echoreply, rtt	# Devuelve una tupla con la respuesta si la hubo y el rtt
	
# Muchos ping a varias direcciones ip cada tanto tiempo tantas veces
# ips: lista de ips a pinguear, cadaCuanto: cada cuanto pinguear en minutos, cuantasVeces: cuantas veces esperar "cadaCuanto" y pinguear, cantPingueos: opcional, cantidad de veces que se pinguea por veces para sacar promedio
def multiping(ips,cadaCuanto,cuantasVeces,cantPingueos=8,timeToLive=64,tOut=1):
	nombreLog = "multiping-"+str(datetime.now()).replace(':', '-').split('.')[0]+".txt"
	cadaCuanto *= 60
	# Hacemos los pingueos
	print("Haciendo multiping")
	promedios = []
	for i in range(cuantasVeces):	# Hago la cantidad de veces solicitada
		print("Tanda "+str(i))
		for ip in ips:	# A cada ip
			tiempo = datetime.now()
			rtts = []
			for j in range(cantPingueos):	# La pingueo la cantidad de veces pedida para sacar un promedio del rtt
				# Pinguear
				echorequest = IP(dst=str(ip),ttl=timeToLive)/ICMP()	# Armo el paquete del ping
				tiempoInicio = datetime.now()	# Tomo tiempo inicial
				echoreply = sr1(echorequest,timeout=tOut,verbose=0)		# Envio y espero a recibir el paquete, verbose hace que no imprima todo por consola
				tiempoFinal = datetime.now()	# Tomo tiempo final
				if type(echoreply) is scapy.layers.inet.IP:		# Si hubo respuesta guardamos el rtt
					rtt = (tiempoFinal - tiempoInicio)	# Rtt en timedelta
					rtt = (rtt.days *  86400000 + rtt.seconds * 1000 + rtt.microseconds / 1000 ) 	# rtt en milisegundos
					rtts.append(rtt)	# Agregamos el rtt a la lista de rtts de esta secuencia de pingueos
			if len(rtts) > 0:	# Si al menos respondieron un ping
				rtt = sum(rtts) / float(len(rtts))	# Sacamos el promedio del rtt
				promedios.append((ip,tiempo,rtt))	# Guardamos los datos de este pingueo 
		print("Tanda "+str(i)+" terminada")
		if(i < (cuantasVeces-1)):
			sleep(cadaCuanto)	# Esperamos a la siguiente tanda de pingueos
	# Guardamos el log
	log = open(nombreLog, 'w')	# Abrimos los logs
	log.write(nombreLog+"\n")
	log.write("Caso: multiping("+str(ips)+","+str(cadaCuanto)+","+str(cuantasVeces)+","+str(cantPingueos)+str(timeToLive)+","+str(tOut)+")\n\n")
	log.write("ip,timestamp pings,rtt\n")
	for ip in ips:	# Para cada ip
		for dato in promedios:	# Guardo los datos de sus pingueos
			if dato[0] == ip:
				log.write(str(dato[0]) + "," + str(dato[1]).split('.')[0] + "," + str(dato[2]) + "\n")
	log.close()	# Cerramos la imagen
	print("Datos guardados en "+nombreLog)
	return 1
	
# Trace route basico
def tracerouteBasico(destino,hopsMax=64,tOut=10):	
	hops = []	# < N° hop , ip , rtt >
	hopsMax += 1
	print("N° hop \t ip \t RTT en ms")
	for ttl in range(1,hopsMax):
		# Hago un promedio entre varios pings para el RTT
		rtts = []
		pingsExitosos = []
		for i in range(3):	# Enviamos tres pings para obtener un rtt promedio y esperando tener al menos una respuesta
			iping = ping(destino,ttl,0,tOut)	# Hago el ping con ttl creciente
			if (type(iping[0]) is scapy.layers.inet.IP) and ICMP in iping[0]:		# Si el ping fue exitoso
				rtts.append(iping[1])	# Agrego el rtt del ping a la lista
				pingsExitosos.append(iping)	# Agrego el ping a la lista	
		# Si hubo algun ping exitoso agrego el hop
		if len(pingsExitosos) > 0:		# Si hubo respuesta
			iping = pingsExitosos[0]
			ipaddress = iping[0][IP].src	# Extraemos el ipaddress del ping
			rtt = sum(rtts) / float(len(rtts))	# El rtt es el promedio de los rtts de los pings exitosos
			hop = (ttl,ipaddress,rtt)	
			if iping[0][ICMP].type == 11:	# Si es de ttl-to-zero-during-transit
				hops.append(hop)	# Agregamos el hop con la ip que contesto, 
			elif iping[0][ICMP].type == 0:	# Si es de echo-reply
				hops.append(hop)	# Agregamos el hop con la ip que contesto
				break
			print(hop)
	print("\nGuardando logs")
	tiempo= str(datetime.now()).replace(':', '-').split('.')[0]	# El nombre es el momento en que se genera
	guardarLogBasico(hops,tiempo,destino)
	return 1

# Super trace route que se muestra en tiempo real con calculo de distancias y posiciones
def superTracerouteRealTime(destino,hopsMax=64,tOut=5):	
	hops = []	# < N° hop , ip , rtt , <latitude, longitude> , distancia respecto al anterior, distancia total, rtt minimo>
	ttl = 0
	ipaddress = getExternalIP()	# mi ip
	coordenadas = geoLocalizar(ipaddress,(0,0))	# coordenadas de mi ip
	coordenadasAnterior = coordenadas	# coordenadas de mi ip
	distanciaAlAnterior = 0
	distanciaParcial = 0
	hop = (ttl,ipaddress,0,coordenadas,distanciaAlAnterior,distanciaParcial,0)
	hops.append(hop) # Le agregamos nuestra ip como hop 0
	hopsMax += 1
	print("N hop \t ip \t RTT en ms \t coordenadas \t Distancia al anterior en km \t Distancia total \t Rtt minimo")
	print(hop)
	for ttl in range(1,hopsMax):
		# Hago un promedio entre varios pings para el RTT
		rtts = []
		pingsExitosos = []
		for i in range(3):	# Enviamos tres pings para obtener un rtt promedio y esperando tener al menos una respuesta
			iping = ping(destino,ttl,0,tOut)	# Hago el ping con ttl creciente
			if (type(iping[0]) is scapy.layers.inet.IP) and ICMP in iping[0]:		# Si el ping fue exitoso
				rtts.append(iping[1])	# Agrego el rtt del ping a la lista
				pingsExitosos.append(iping)	# Agrego el ping a la lista	
		# Si hubo algun ping exitoso agrego el hop
		if len(pingsExitosos) > 0:		# Si hubo respuesta
			iping = pingsExitosos[0]
			ipaddress = iping[0][IP].src	# Extraemos el ipaddress del ping
			rtt = sum(rtts) / float(len(rtts))	# El rtt es el promedio de los rtts de los pings exitosos
			coordenadas = geoLocalizar(ipaddress,coordenadasAnterior)	# Buscamos las coordenadas de la ip, si no se consiguen se mantienen las del anterior
			distanciaAlAnterior = haversine(coordenadasAnterior[1], coordenadasAnterior[0], coordenadas[1], coordenadas[0])	# Calculamos la distancia al anterior
			distanciaParcial	+= distanciaAlAnterior
			hop = (ttl,ipaddress,rtt,coordenadas,distanciaAlAnterior,distanciaParcial,rttMinimo(distanciaParcial))	
			if iping[0][ICMP].type == 11:	# Si es de ttl-to-zero-during-transit
				hops.append(hop)	# Agregamos el hop con la ip que contesto, 
			elif iping[0][ICMP].type == 0:	# Si es de echo-reply
				hops.append(hop)	# Agregamos el hop con la ip que contesto
				break
			coordenadasAnterior = coordenadas
			print(hop)
	print("\nGenerando mapa")
	nombre = str(datetime.now()).replace(':', '-').split('.')[0]	# El nombre es el momento en que se genera
	listaCoordenadas = [h[3] for h in hops]	# Lista con las coordenadas de cada hop
	urlMapa = guardarMapa(listaCoordenadas,nombre)	# Generamos un mapa del traceroute
	print("\nGuardando logs")
	guardarLog(hops,nombre,urlMapa,destino)
	return 1
	
# Devuelve mi direccion ip externa
def getExternalIP():
    #req = request.Request('http://jsonip.com/')
    response = request.urlopen('http://jsonip.com/')	# Abrimos jsonip.com para que nos diga nuestra ip externa
    jsonip = json.loads(response.read().decode("utf-8"))	# Pasamos jsonip.com a diccionario con strings
    return str(jsonip['ip'])
	
# Devuelve la latitud y longitud de una ip, recibe una ip y una coordenada anterior, si da error (la ip es privada o no hay datos disponibles) devuelve la coordenada anterior
def geoLocalizar(ipaddress,coordenadaAnterior=(0,0)):
	url = 'http://dazzlepod.com/ip/'+ipaddress+'.json'	# Url del servicio de geolocalizacion gratuito
	req = request.Request(url)	# Le mandamos un request a la url para que nos devuelva la geolocalizacion de la ip
	try:
		response = request.urlopen(req)	# Abrimos la respuesta del request
	except request.URLError as e:
		return coordenadaAnterior
	geoDatosIp = json.loads(response.read().decode("utf-8"))	# json.loads: pasa string de json a diccionario, decode pasa los bytes de la respuesta a string, response.read pasa la respuesta http a datos bytes
	if 'error' in geoDatosIp:	
		return coordenadaAnterior
	else:
		return (geoDatosIp["latitude"],geoDatosIp["longitude"])	# Devuelvo las coordenadas del host a la lista
	
# Funcion para calcular la distancia en kilometros entre dos coordinadas terrestres
def haversine(lon1, lat1, lon2, lat2):
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])	# convert decimal degrees to radians 
    # haversine formula 
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    km = 6371 * c	# 6371: Radio medio de la tierra
    return km 
	
# Devuelve el rtt minimo para una distancia en kilimetros en base al tiempo de propagacion del enunciado
def rttMinimo(distancia):
	global tiempoPropagacion
	return distancia / tiempoPropagacion
    
# Guarda un mapa en png basado en google static maps, recibe una lista de coordenadas (latitud,longitud) y el nombre del mapa opcionalmente
def guardarMapa(hops,nombre="mapaSinNombre"):
	tags = dict()
	for index in range(10):
		tags[str(index)] = str(index)
	for index, letra in enumerate(string.ascii_uppercase):
		tags[str(index+10)] = letra
	nombre += ".png"
	urlMapsBase = 'http://maps.googleapis.com/maps/api/staticmap?zoom=1&size=600x400&scale=2&sensor=false&maptype=roadmap'	# Url base para pedir la imagen
	url = urlMapsBase	# url que vamos a ir formando
	path = "&path=color:0xff0000|weight:2"	# Base del camino
	for i, pin in enumerate(hops):
		#url += "&markers=label:"+str(i)+"|"+str(pin[0])+","+str(pin[1])	# Le agregamos un pin al mapa
		tag="."
		if str(i) in tags:
			tag = tags[str(i)]
		url += "&markers=label:"+tag+"|"+str(pin[0])+","+str(pin[1])	# Le agregamos un pin al mapa
		path += "|"+str(pin[0])+","+str(pin[1])	# Le agremos el punto al camino
	url += path	# Agregamos el camino al mapa
	# Le pedimos a google que haga nuestro mapa y lo guardamos
	req = request.Request(url)	# Le mandamos un request a google static maps para que nos devuelva un png con el traceroute
	imagen = open(nombre, 'wb')	# Abrimos un archivo para guardar datos binario
	response = request.urlopen(req)	# Obtenemos  la respuesta del pedido a google maps static 
	imagen.write(response.read())	# Guardamos la imagen recibida por google maps
	imagen.close()	# Cerramos la imagen
	print("Mapa",nombre,"guardado")
	return url
	
# Guardar log traceroute basico
def guardarLogBasico(hops,tiempo,destino):
	logs = open("logs.txt", 'a')	# Abrimos los logs
	logs.write("------------------------------------------\n")
	logs.write("-          "+tiempo+"           -\n")
	logs.write("------------------------------------------\n")
	logs.write("Destino: "+str(destino)+"\n")
	logs.write("N° hop,ip,RTT en ms\n")
	for hop in hops:
		logs.write(str(hop[0])+","+hop[1]+","+str(hop[2])+"\n")
	logs.close()	# Cerramos la imagen
	return 1
	
# Guardar log, el tiempo en que se termino y la url del mapa generado
def guardarLog(hops,tiempo,urlMapa,destino):
	logs = open("logs.txt", 'a')	# Abrimos los logs
	logs.write("------------------------------------------\n")
	logs.write("-          "+tiempo+"           -\n")
	logs.write("------------------------------------------\n")
	logs.write("Destino: "+str(destino)+"\n")
	logs.write("N° hop,ip,RTT en ms,coordenadas,Distancia al anterior en km,Distancia total,RTT minimo\n")
	for hop in hops:
		logs.write(str(hop[0])+","+hop[1]+","+str(hop[2])+",("+str(hop[3][0])+","+str(hop[3][1])+"),"+str(hop[4])+","+str(hop[5])+","+str(hop[6])+"\n")
	logs.write("\nMapa:\n")
	logs.write(urlMapa+"\n")
	logs.close()	# Cerramos la imagen
	return 1

# Imprimir menu main
def printMenu():
	print("**************************************")
	print("Redes - capa de red")
	print("1. Ping")
	print("2. Multiping")
	print("3. Traceroute basico")
	print("4. Super traceroute")
	print("5. Geolocalizar ip")
	print("6. Ayuda")
	print("0. Salir")
	print("**************************************")
	return 1
	
# Imprimir ayuda
def printAyuda():
	print("**************************************")
	print("*               Ayuda                *")
	print("**************************************")
	print("1. Ping")
	print("Se le da una ip y se le hace un ping. Si conteste se confirma y presenta el rtt.")
	print("Por linea de commandos: tp2.py ping -ip $ip (opcionales:) -ttl $ttl -to $timeout_en_segundos\n")
	
	print("2. Multiping")
	print("Se le da una o varias ips y hace ping a esas ips cada x tiempo n veces.")
	print("Por linea de commandos: tp2.py multiping -ips $ip1 $ip2 ... $ipk (opcionales:) -t $tiempo_entre_pings -c $cantidad_de_tandas -p $cantidad_de_pingueos_para_hacer_promedio -ttl $ttl -to $timeout_en_segundos\n")
	
	print("3. Traceroute basico")
	print("Se le da una u muestra el traceroute.")
	print("Por linea de commandos: tp2.py traceroute -ip $ip (opcionales:) -hm $hops_maximos -to $timeout_en_segundos\n")
	
	print("3. Super traceroute")
	print("Traceroute que va mostrando coordenadas del host, distancia al anterior, distancia recorrida total, rtt, rtt minimo teorico y al final genera un mapa del recorrido")
	print("Por linea de commandos: tp2.py straceroute -ip $ip (opcionales:) -hm $hops_maximos -to $timeout_en_segundos\n")
	
	print("4. Geolocalizar")
	print("Devuelve las coordenadas terrestres (latitud,longitud) de una ip o web. Si no hay informacion disponible devuelve (0,0)")
	print("Por linea de commandos: tp2.py geolocalizar -ip $ip\n")
	
	return 1
	
# Manejar los argumentos si corre por consola
def parsearArgumentosCorrerPorConsola():
	if sys.argv[1] == "ping":
		#~ ping(ip,timeToLive=64,imprimir=1,tOut=10)
		#~ -ip -ttl -v -to  
		ttl = 64	# Hops maximos por defecto
		to = 5	# Timeout por defecto
		verbose = 1	# Imprimir por consola la parte de enviar paquetes y recibidos de scapy
		if '-ttl' in sys.argv:	# si dan timeout uso ese
			to = int(sys.argv[sys.argv.index('-ttl')+1])
		if '-to' in sys.argv:	# si dan timeout uso ese
			to = int(sys.argv[sys.argv.index('-to')+1])
		if '-v' in sys.argv:	# si dan verbose uso ese
			verbose = int(sys.argv[sys.argv.index('-v')+1])
		if '-ip' in sys.argv:	# Si dan ip uso esa
			ip = sys.argv[sys.argv.index('-ip')+1]
		else:	# Si no dan ip destino salimos
			print("No se indico ip o web a pinguear")
			return 0
		ping(ip,ttl,verbose,to)
	elif sys.argv[1] == "multiping":
		#~ multiping(ips,cadaCuanto,cuantasVeces,cantPingueos=8,timeToLive=64,tOut=1)
		#~ -ips -t -c -p -ttl -to
		t = 60	# Default 60 minutos
		c = 6	# Default 6 tandas
		p = 3	# Default 3 pingueos para sacar promedio rtt
		ttl = 64	# Hops maximos por defecto
		to = 5	# Timeout por defecto
		indicesEtiquetas = []	# Indices de -t -c -p -ttl -to
		if '-t' in sys.argv:
			posT = sys.argv.index('-t')
			t = float(sys.argv[posT+1])
			indicesEtiquetas.append(posT)
		if '-c' in sys.argv:
			posC = sys.argv.index('-c')
			c = int(sys.argv[posC+1])
			indicesEtiquetas.append(posC)
		if '-p' in sys.argv:
			posP = sys.argv.index('-p')
			p = int(sys.argv[posP+1])
			indicesEtiquetas.append(posP)
		if '-ttl' in sys.argv:
			posTtl = sys.argv.index('-ttl')
			ttl = int(sys.argv[posTtl+1])
			indicesEtiquetas.append(posTtl)
		if '-to' in sys.argv:
			posTo = sys.argv.index('-to')
			to = int(sys.argv[posTo+1])
			indicesEtiquetas.append(posTo)
		if '-ips' in sys.argv:
			posIps = sys.argv.index('-ips')
		else:	# Si no dan ips destino salimos
			print("No se indicaron ips o webs a pinguear")
			return 0
		indicesEtiquetas = [(i-posIps) for i in indicesEtiquetas if (i-posIps) > 0]
		if len(indicesEtiquetas) == 0:
			ips = sys.argv[posIps+1:]
		else:
			ips = sys.argv[posIps+1:posIps+min(indicesEtiquetas)]
		multiping(ips,t,c,p,ttl,to)
	elif sys.argv[1] == "traceroute" or sys.argv[1] == "straceroute":
		#~ tracerouteBasico(destino,hopsMax=64,tOut=10)
		#~ superTracerouteRealTime(destino,hopsMax=64,tOut=5)
		hm = 64	# Hops maximos por defecto
		to = 5	# Timeout por defecto
		if '-hm' in sys.argv:	# si dan hops max uso ese
			hm = int(sys.argv[sys.argv.index('-hm')+1])
		if '-to' in sys.argv:	# si dan timeout uso ese
			to = int(sys.argv[sys.argv.index('-to')+1])
		if '-ip' in sys.argv:	# Si dan ip uso esa
			ip = sys.argv[sys.argv.index('-ip')+1]
		else:	# Si no dan ip destino salimos
			print("No se indico ip o web a pinguear")
			return 0
		if sys.argv[1] == "traceroute":
			tracerouteBasico(ip,hm,to)
		elif sys.argv[1] == "straceroute":
			superTracerouteRealTime(ip,hm,to)
	elif sys.argv[1] == "geolocalizar":
		if '-ip' in sys.argv:	# Si dan ip uso esa
			ip = sys.argv[sys.argv.index('-ip')+1]
		else:	# Si no dan ip destino salimos
			print("No se indico ip o web a pinguear")
			return 0
		print(geoLocalizar(ip))
	elif sys.argv[1] == "-h":
		printAyuda()
	return 1

# Main
def main():
	if len(sys.argv) > 1:	# Si pasan argumentos lo corremos por consola
		parsearArgumentosCorrerPorConsola()
	else:	# Si no pasan argumentos ponemos menu
		try: input = raw_input  # Fix python 2.x para usar input como raw_input
		except NameError: pass  # Fix python 2.x para input
		ip = ""
		while True:
			printMenu()		# Imprimo el menu
			opcion = input("Opcion: ")	# Selecciono item del menu
			if opcion == "1":	# Ping
				#print("Ip o web, ttl (opcional), verbose (0 o 1, opcional), timeout (opcional)")
				#parametros = input("Parametros: ")	# Ingreso ip
				ip = input("Ip o web: ")	# Ingreso ip
				ping(ip)
			elif opcion == "2":	#  Multiping
				ips = input("Ips o webs separados por un espacio: ")	# Ingreso ips
				ips = ips.split(' ')	# Separo las ip por los espacios en blanco, queda una lista
				tandas = int(input("Cuantas tandas de pings: "))
				espera = float(input("Espera en minutos entre tandas: "))
				cantiPings = int(input("Cantidad de pingueos a la misma ip para sacar promedio del RTT: "))
				multiping(ips,espera,tandas,cantiPings)
			elif opcion == "3":	# Traceroute basico
				#print("Ip o web, hops maximos, timeout (opcional)")
				#parametros = input("Parametros: ")	# Ingreso ip
				ip = input("Ip o web: ")	# Ingreso ip
				tracerouteBasico(ip)
			elif opcion == "4":	# Traceroute super
				#print("Ip o web, hops maximos, timeout (opcional)")
				#parametros = input("Parametros: ")	# Ingreso ip
				ip = input("Ip o web: ")	# Ingreso ip
				superTracerouteRealTime(ip)
			elif opcion == "5":	# Geolocalizar ip
				ip = str(input("Ip: "))	# Ingreso ip
				print(geoLocalizar(ip))
			elif opcion == "6":	# Imprimir ayuda
				printAyuda()
			elif opcion == "0":
				break
	return 1


main()
#superTraceroute("173.194.42.8")
#superTracerouteRealTime("173.194.42.8")	# ping google
#superTracerouteRealTime("220.181.111.85")	# ping baidu
#multiping(["74.125.234.225","193.145.222.100"],1,2,6)
