import socket
import datetime
import argparse
import dnsparser
import pickle

def response_isValid():
    return True

def requestFiltered(question, filters):
    """
    Looks up for REDIRECTS or FORBIDEN questions on a filter dict
    Args
        -question, dns unpacked question
        -filters, a dictionary with question - procedure pairs
    Return
        - Altered response or empty string if none defined
    """
    return ""

def cacheLookup(question, cache):
    """
    Looks up the requested domain on a cache
    Args
        -question, dns unpacked question
        -cache, a dictionary with domain - response pairs
    Return
        - Values from cache or empty string if failed
    """
    return ""

def main(localPort, dns_resolver):

    # Load files for log, cache and filters
    log_file = open("Log.txt", "a")
    cache_file = open("Cache.txt", "a")
    cache_dict = {}
    #filters_file = open("Filters.txt","rw")

    localIP = "127.0.0.1"

    BUFFERSIZE = 1024
    DEFAULT_TIMEOUT_SECS = 5

    # Create two datagram sockets
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPProxySocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # Set default timeouts
    UDPServerSocket.settimeout(DEFAULT_TIMEOUT_SECS)
    UDPProxySocket.settimeout(DEFAULT_TIMEOUT_SECS)

    # Bind to address and ip
    UDPServerSocket.bind((localIP, localPort))
    UDPProxySocket.connect((dns_resolver, 53))

    print("UDP server up and listening")

    # Listen for incoming datagrams
    try:
        while True:
            try:
                message, address = UDPServerSocket.recvfrom(BUFFERSIZE)

                clientMsg = "mensaje:{}".format(message)
                clientIP = "IP:{}".format(address)
                actualTime = datetime.datetime.now()
                log_file.write("Recibido mensaje del cliente el %s, desde la %s, con el %s.\n" % (actualTime.strftime("%d/%m/%y a las %H:%M:%S"), clientIP, clientMsg))

                # Parse and validate request
                headerC, questionsC = dnsparser.unpackDNS(message)
                print(headerC,questionsC)
                id = headerC['ID']
                # Check if the request is a query
                if headerC['QR']:
                    # Check domain name not in filter
                    for q in questionsC:
                        res = requestFiltered(q,None) # TODO
                        if res != "":
                            # Reply to client *cache values should be stored in bytes
                            UDPServerSocket.sendto(res, address)
                            actualTime = datetime.datetime.now()

                    # Check if domain's in cache
                    for q in questionsC:
                        res = cacheLookup(q, cache_dict) # TODO
                        if res != "":
                            # Reply to client *cache values should be stored in bytes
                            UDPServerSocket.sendto(res, address)
                            actualTime = datetime.datetime.now()

                    # Check that the request is supported
                    # TODO
                    
                else:
                    print("Message rejected: Not a query")
                    continue

                # Send query to resolver and recover response
                # If resolver can't be reached log NO CONNECTION error
                try:
                    UDPProxySocket.send(message)
                    resolverResponse, resolverAddress = UDPProxySocket.recvfrom(BUFFERSIZE)

                    # Get the response value's of interest
                    headerR, questionsR = dnsparser.unpackDNS(resolverResponse)
                    print(headerR,questionsR)
                    cache_dict[questionsC]=resolverResponse
                    #To modify ID:
                    #resolverModified = bytearray(resolverResponse)
                    #resolverModified[0],resolverModified[1] = (id+1).to_bytes(2, byteorder='big')[0],(id+1).to_bytes(2, byteorder='big')[1]
                    #resolverModified = bytes(resolverModified)
                    # Reply to client
                    UDPServerSocket.sendto(resolverModified, address)
                    actualTime = datetime.datetime.now()

                    # Loggin response
                    if response_isValid():
                        log_file.write("Respondido a la %s con el mensaje %s, el %s.\n" % (clientIP, resolverResponse, actualTime.strftime("%d/%m/%y a las %H:%M:%S")))
                    else:
                        log_file.write("La consulta de la %s no es valida el %s.\n" % (clientIP, actualTime.strftime("%d/%m/%y a las %H:%M:%S")))

                except socket.timeout:
                    log_file.write("La consulta de la %s no pudo ser completada el %s.\n" % (clientIP, actualTime.strftime("%d/%m/%y a las %H:%M:%S")))
            except socket.timeout:
                print("Time out")
    except KeyboardInterrupt:
        pass
        
    print("Closing server ...")
    UDPProxySocket.close()
    UDPServerSocket.close()
    log_file.close()
    cache_file.close()
    #filters_file.close()

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="port to listen for DNS requests", default="8001", type=int)
    parser.add_argument("--resolver_dns", help="DNS resolver for queries", default="8.8.8.8")
    args = parser.parse_args()

    main(args.port, args.resolver_dns)
