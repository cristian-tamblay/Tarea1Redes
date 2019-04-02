import socket as libsock
import random
import struct

addr = "127.0.0.1"
port = 20001

def run_client():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    socket.connect((addr, port)) # SOCK_DGRAM es UDP
    print("Saludando al servidor {}:{}...".format(addr, port))
    socket.send("hola\n".encode()) # El saludo
    data, address = socket.recvfrom(1024) # Escucho para ver qué recibo
    print("Binario recibido, ahora lo parsearé...")
    h, s= struct.unpack("8s8s", data) # Hago unpack de la info recibida
    response = "{}{}".format(h.decode(), s.decode()) # la formateo como texto
    print("Enviaré esta respuesta: " + response) # esta es la cadena formateada como sale en el enunciado
    socket.sendto(response.encode(), address) # y la envío de vuelta
    print("Cupón enviado, esperando respuesta...")
    data, _ = socket.recvfrom(1024) # espero haber enviado la cadena correcta
    print("El servidor me dijo: \"{}\"".format(data.decode().strip())) # respuesta del servidor

run_client()