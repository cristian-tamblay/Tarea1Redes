import socket
import sys
import datetime

def question_isValid():
    return True

def main(localPort):
    log_file = open("Log.txt", "w")
    localIP = "127.0.0.1"

    bufferSize = 1024

    msgFromServer = "Hello UDP Client"

    bytesToSend = str.encode(msgFromServer)

    # Create a datagram socket

    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # Bind to address and ip

    UDPServerSocket.bind((localIP, localPort))

    print("UDP server up and listening")

    # Listen for incoming datagrams
    while True:
        bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)

        message = bytesAddressPair[0]
        address = bytesAddressPair[1]

        clientMsg = "mensaje:{}".format(message)
        clientIP = "IP:{}".format(address)
        actualTime = datetime.datetime.now()
        log_file.write("Recibido mensaje del cliente el %s, desde la %s, con el %s." % (actualTime.strftime("%d/%m/%y a las %H:%M:%S"), clientIP, clientMsg))
        print(clientMsg)
        print(clientIP)

        # Sending a reply to client
        # Loggin response

        UDPServerSocket.sendto(bytesToSend, address)
        actualTime = datetime.datetime.now()

        if question_isValid():
            log_file.write("Respondido a la %s con el mensaje %s, el %s." % (clientIP, 'mensaje del DNS', actualTime.strftime("%d/%m/%y a las %H:%M:%S")))
        else:
            log_file.write("La consulta de la %s no es valida el %s" % (clientIP, actualTime.strftime("%d/%m/%y a las %H:%M:%S")))


if __name__ == "__main__":
    main(int(sys.argv[1]))
