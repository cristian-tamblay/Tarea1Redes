import struct
import ipaddress
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
        - A list of parsed Queries in dict format
        - Number of bytes read

    Reference:
    https://tools.ietf.org/html/rfc1035 Section 4.1.2
    """
    if nQuestions == 0:
        return None, 0

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
        QTYPE, QCLASS = struct.unpack_from(">HH",byteArray,byte_offset)

        byte_offset += 4 

        questions.append({
            'QNAME': domain_name, 'QTYPE': QTYPE, 'QCLASS': QCLASS
        })

    return questions, byte_offset


def validateRData(Type, Class, byteArray):
    """
    Given the type of a RR parse it according to 
    the specifications in 
    https://tools.ietf.org/html/rfc1035 Section 3.1.3
    Args
        -Type of RR
        -Class of RR
        -The data in byteArrayformat
    Return
        - A tuple of a a boolean (if is valid) and a the result.
    Info: RDATA Supported
        - A
        - AAAA
        - MX
    """

    if Type == 1 and Class == 1 and len(byteArray) == 4:
        # A and IN -> Read IPV4
        return True, str(ipaddress.IPv4Address(byteArray))
    elif Type == 28 and Class == 1 and len(byteArray) == 16:
        # AAAA and IN -> Read IPV6
        return True, str(ipaddress.IPv6Address(byteArray))
    elif Type == 15 and Class == 1:
        # Get the preference
        PREF = struct.unpack(">H",byteArray[:2])
        # Parse the domain name
        byte_offset = 2
        domain_name = ""
        while True:
            val = struct.unpack_from(">c",byteArray,byte_offset)
            name_lenght = int.from_bytes(val[0],byteorder='little')
            byte_offset += 1
            if name_lenght == 0:
                break
            # Case found when asking for cnn.com
            # The com. would be received as 0xc0 0x10
            # instead of the standard 0x03 com 0x00
            if val[0] == b'\xc0':
                domain_name += "com."
                break
            current_name = struct.unpack_from("{}s".format(name_lenght),byteArray,byte_offset)
            byte_offset += name_lenght
            domain_name += current_name[0].decode() + "."
        return True, {'PREF': PREF[0], 'DNAME': domain_name}
    
    return False, None


def unpackAnswers(byteArray, nAns):
    """
    For each Resource Record parse the answers
    Args
        -byteArray dns message
        -nQuestions, number of questions to consider
    Return
        - A list of parsed RR in dict format

    Reference:
    https://tools.ietf.org/html/rfc1035 Section 4.1.3
    """

    answers = list()
    byte_offset = 0

    # For each answer
    for _ in range(nAns):
        
        # We check if its separated by the marker 0xc00c
        # This wasn't found in the Docs!
        l,r = struct.unpack("BB",byteArray[:2])
        if l != 0xc0 and r != 0x0c:
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
        else: 
            domain_name = "Same as query"
            byte_offset += 2

        # We extract the type and class
        TYPE, CLASS, TTL, RDLENGTH = struct.unpack_from(">HHIH",byteArray,byte_offset)
        byte_offset += 10

        # Validate Answers
        if CLASS > 4:
            raise Exception("Not a valid class for RR")

        isValid, RDATA = validateRData(TYPE, CLASS, byteArray[byte_offset:byte_offset+RDLENGTH])
        if not isValid:
            raise Exception("Ouch not a supported type class pair")

        answers.append({
            'DNAME': domain_name, 'TYPE': TYPE, 'CLASS': CLASS, 'TTL': TTL, 'RDATA': RDATA
        })

        byte_offset += RDLENGTH

    return answers, byte_offset


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
    question, offset = unpackQuestions(byteArray[12:], header['QDCOUNT'])
    offset += 12

    # Parse responses and get TTL
    if header['ANCOUNT'] !=  0:
        responses, offset = unpackAnswers(byteArray[offset:], header['ANCOUNT'])
    else:
        responses = None
    return header, question, responses
