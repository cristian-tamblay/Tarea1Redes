import socket
import datetime
import argparse
import dnsparser
import pickle
import time
import os

def response_isValid():
    return True

def requestFiltered(question, filters, resolverFormat):
    """
    Looks up for REDIRECTS or FORBIDEN questions on a filter dict
    Args
        -question, dns unpacked question
        -filters, a dictionary with question - procedure pairs
    Return
        - Altered response or empty string if none defined
    """
    resolver = bytearray(resolverFormat)
    domain = question['QNAME'][:-1]
    filter_response = filters.get(domain, "")
    if filter_response == "forbidden":
        return ""
    elif filter_response != "":
        filter_response = filter_response.split('.')
        filter_response = list(map(int,filter_response))
        inicial = 13+len(domain)+17
        resolver[inicial],resolver[inicial+1],resolver[inicial+2],resolver[inicial+3] = (filter_response[0]).to_bytes(1, byteorder='big')[0],\
                                                              (filter_response[1]).to_bytes(1, byteorder='big')[0],\
                                                              (filter_response[2]).to_bytes(1, byteorder='big')[0],\
                                                              (filter_response[3]).to_bytes(1, byteorder='big')[0]
        return resolver
    return ""

def cacheLookup(question, cache, id):
    """
    Looks up the requested domain on a cache
    Args
        -question, dns unpacked question
        -cache, a dictionary with domain - response pairs
        -id from the client
    Return
        - Values from cache or empty string if failed
    """
    response = cache.get(repr(question), "")
    if response != "":
        response = bytearray(response)
        response[0], response[1] = id.to_bytes(2, byteorder='big')[0], id.to_bytes(2, byteorder='big')[1]
    return response

def main(localPort, dns_resolver):

    # Load files for log, cache and filters

    log_file = open("Log.txt", "a")
    # Add Dict to cache_file
    pickle.dump({}, open('Cache.txt', 'wb'), protocol=pickle.HIGHEST_PROTOCOL)

    # Create filter dictionary using Filters.txt
    filters_file = open("Filters.txt","r")
    filters_dict = {}
    for line in filters_file:
        filters = line.split()
        filters_dict[filters[0]] = filters[1]
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
            elapsedTime = time.time()-os.path.getctime("Cache.txt")
            if elapsedTime > 100:
                with open('Cache.txt', 'wb') as handle:
                    cache_dict = {}
                    pickle.dump(cache_dict, handle, protocol=pickle.HIGHEST_PROTOCOL)
                print("Deleted cache!")
            try:
                message, address = UDPServerSocket.recvfrom(BUFFERSIZE)

                clientMsg = "mensaje:{}".format(message)
                clientIP = "IP:{}".format(address)
                actualTime = datetime.datetime.now()
                log_file.write("Recibido mensaje del cliente el %s, desde la %s, con el %s.\n" % (actualTime.strftime("%d/%m/%y a las %H:%M:%S"), clientIP, clientMsg))

                # Parse and validate request
                headerC, questionsC, responsesC = dnsparser.unpackDNS(message)
                print(headerC,questionsC, responsesC)
                id = headerC['ID']
                # Check if the request is a query
                if headerC['QR']:
                    # Load data (deserialize)
                    with open('Cache.txt', 'rb') as handle:
                        cache_dict = pickle.load(handle)

                    # Check if domain's in cache
                    cache_counter = 0
                    for q in questionsC:
                        res = cacheLookup(q, cache_dict, id)
                        if res != "":
                            # Reply to client *cache values should be stored in bytes
                            UDPServerSocket.sendto(res, address)
                            actualTime = datetime.datetime.now()
                            cache_counter += 1

                    # Check if we had all the answers
                    if cache_counter == len(questionsC):
                        continue

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
                    headerR, questionsR, responsesR = dnsparser.unpackDNS(resolverResponse)
                    print(headerR,questionsR,responsesR)
                    # Check domain name not in filter
                    for q in questionsC:
                        res = requestFiltered(q, filters_dict, resolverResponse)
                        if res != "":
                            # Reply to client *cache values should be stored in bytes
                            UDPServerSocket.sendto(res, address)
                            actualTime = datetime.datetime.now()
                            with open('Cache.txt', 'rb') as handle:
                                cache_dict = pickle.load(handle)
                            for q in questionsC:
                                cache_dict[repr(q)] = res
                            with open('Cache.txt', 'wb') as handle:
                                pickle.dump(cache_dict, handle, protocol=pickle.HIGHEST_PROTOCOL)

                        else:
                            # Bring cache_file to RAM
                            with open('Cache.txt', 'rb') as handle:
                                cache_dict = pickle.load(handle)

                            # Save Resolver Response to Dict
                            for q in questionsC:
                                cache_dict[repr(q)] = resolverResponse

                            # Store data (serialize)
                            with open('Cache.txt', 'wb') as handle:
                                pickle.dump(cache_dict, handle, protocol=pickle.HIGHEST_PROTOCOL)

                            # Reply to client
                            UDPServerSocket.sendto(resolverResponse, address)
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
    #filters_file.close()

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="port to listen for DNS requests", default="8001", type=int)
    parser.add_argument("--resolver_dns", help="DNS resolver for queries", default="8.8.8.8")
    args = parser.parse_args()

    main(args.port, args.resolver_dns)
