import socket
import glob
import json

port = 53 #default DNS operation port
ip = '127.0.0.1' #localhost IP

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():

    jsonObjs = {} #array with dictionaries
    with open('dns.json') as dnsObjs:
        jsonObjs = json.load(dnsObjs)

    zones = {} #array with json objects with key->"$original"

    for item in jsonObjs:
        for key in item:
            zonename = item["$original"]
            zones[zonename] = item
            break

    return zones

zonedata = load_zones()

#   Build flags for DNS response
#   params: [bytes] 2 bytes offset from DNS query
#   return: [string] 2 bytes of flags sections 
def getflags(flags):

    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    #Byte 1
    QR = '1'
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))
    AA = '1'
    TC = '0'
    RD = '0'

    #Byte 2
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big') + int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0 # iterator to the end of data field
    for byte in data:
        if state == 1:
            if byte != 0: #check that it's not first (empty) byte
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0: # if we iterate to end of string (0x00 byte)
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte #first byte - empty
        y += 1

    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    domain, questiontype = getquestiondomain(data)

    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'
    
    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
        
    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder="big")

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    
    return rbytes

#Build DNS response
def buildresponse(data):
    
    #Transactions ID [0-1 bytes]
    TransactionID = data[:2] #Array with 2 bytes of ID DNS-header

    #Get the flags [2-3 bytes]
    Flags = getflags(data[2:4])

    #Question Count
    QDCOUNT = b'\x00\x01'

    #Answer Count (count of strings in the one zone)
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    #Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    #Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
    
    #Create DNS body
    dnsbody = b''

    #Get answer for query
    records, rectype, domainname = getrecs(data[12:])
    
    dnsquestion = buildquestion(domainname, rectype)
    
    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody


while 1:
    data, addr = sock.recvfrom(512) #UDP msg length (bytes)
    r = buildresponse(data)
    sock.sendto(r, addr)


