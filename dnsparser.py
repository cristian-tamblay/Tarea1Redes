import struct
"""
For further implementation reference go to
https://tools.ietf.org/html/rfc1035
https://docs.python.org/3/library/struct.html
"""

def get_bit(byteval,idx):
    """
    Get the bit on index idx from least to most significant
    from right to left
    """
    return ((byteval&(1<<idx))!=0)

def unpackHeader(byteArray):
    """
    Recover the header of a DNS Query from a bytearray
    Args
        -byteArray of 12 bytes
    Return
        - Dictionary with the Header

    Reference:
    https://tools.ietf.org/html/rfc1035 Section 4.1.1
    """
    h = dict()

    ID, h1, h2, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack(">HBBHHHH",byteArray)

    h['ID'] = ID
    h['QR'] = not get_bit(h1,7) # Tru if is a Query, else False

    if get_bit(h1,3) and get_bit(h1,4):
        h['OPCODE'] = 2 # STATUS 
    elif get_bit(h1,3):
        h['OPCODE'] = 1 # IQUERY
    else:
        h['OPCODE'] = 0 # QUERY
    
    h['AA'] = get_bit(h1,2)
    h['TC'] = get_bit(h1,1)
    h['RD'] = get_bit(h1,0)
    h['RA'] = get_bit(h2,7)

    # To only consider the least significant  bits
    # we do a 8bit inversion. The bits 5 to 7 are always empty 
    byteInversion = 0xef 
    h['RCODE'] = int( h2 & byteInversion)

    h['QDCOUNT'] = QDCOUNT
    h['ANCOUNT'] = ANCOUNT
    h['NSCOUNT'] = NSCOUNT
    h['ARCOUNT'] = ARCOUNT

    return h

def unpackQuestions(byteArray, nQuestions):
    """
    Recover the questions of a DNS Query from a bytearray
    Args
        -byteArray dns message
        -nQuestions, number of questions to consider
    Return
        - Dictionary with the Header, Question, Answer, Authority, Additional

    Reference:
    https://tools.ietf.org/html/rfc1035 Section 4.1.2
    """

    questions = list()
    byte_offset = 0

    # For each question
    for _ in range(nQuestions):

        # We loop through each 16bit block to get the name
        domain_name = ""
        while True:
            val = struct.unpack_from(">cx",byteArray,byte_offset)
            name_lenght = int.from_bytes(val[0],byteorder='little')
            byte_offset += 1
            if name_lenght == 0:
                break
            current_name = struct.unpack_from("{}s".format(name_lenght),byteArray,byte_offset)
            byte_offset += name_lenght
            domain_name += current_name[0].decode() + "."

        # We extract the type and class
        if byte_offset%2 != 0:
            byte_offset += 1

        QTYPE, QCLASS = struct.unpack_from(">HH",byteArray,byte_offset)

        questions.append({
            'QNAME': domain_name, 'QTYPE': QTYPE, 'QCLASS': QCLASS
        })

    return questions

def unpackDNS(byteArray):
    """
    Recover the sections of a DNS Query from a bytearray
    Args
        -byteArray dns message
    Return
        - Dictionary with the Header, Question, Answer, Authority, Additional

    Reference:
    https://tools.ietf.org/html/rfc1035 Section 4.1
    """

    # Get the header (First 12 bytes)
    header = unpackHeader(byteArray[:12])

    # Get the Question if it applies
    if header['QR']:
        question = unpackQuestions(byteArray[12:], header['QDCOUNT'])
    else:
        question = None

    # TODO: parse responses and get TTL

    return header, question
