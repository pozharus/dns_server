import socket
import json
import sys

class DNS_server:

    # Default parameters
    ip = '127.0.0.1'
    port = 53
    # Map for storing JSON objects that represent zone info
    # key(domain-name) -> value(object)
    zone_data = {}
     
    def __init__(self):
        # Get parameters from cmd if it puts
        if len(sys.argv) > 1:
            self.ip = sys.argv[1]
            self.port = sys.argv[2]    
            
        self.loadZones()

    def loadZones(self):
        
        jsonObjs = {} #array with dictionaries
        with open('dns.json') as dnsObjs:
            jsonObjs = json.load(dnsObjs)

        zones = {} #array with json objects with key->"$original"

        for item in jsonObjs:
            for key in item:
                zonename = item["$original"]
                zones[zonename] = item
                break

        self.zone_data = zones

    def getFlags(self, data):
        # byte1:
        # QR (1 bit)
        QR = '1'
        # Opcode (4 bit)
        byte1 = data[:1]
        Opcode = ''
        for bit in range(1,5):
            Opcode += str(ord(byte1)&(1<<bit)) # Copyright - https://youtu.be/4I9LEY-q-co
        # AA (1bit)
        AA = '1'
        # TC (1 bit)
        TC = '0'
        # RD (1 bit)
        RD = '0'

        # byte2:
        # RA (1 bit)
        RA = '0'
        # Z (3 bit)
        Z = '000'
        # RCODE (4 bit)
        RCODE = '0000'

        res_byte1 = int(QR+Opcode+AA+TC+RD, 2).to_bytes(1, byteorder='big')
        res_byte2 = int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

        return res_byte1 + res_byte2

    def getQuestionDomain(self, data):
        domain_parts = []
        domain_part = ''
        empty_byte = ''
        it = 0
        it_end_dmn = 0
        flag = 0

        for byte in data:
            if flag == 1:
                if byte != 0:
                    # not empty
                    domain_part += chr(byte)
                it += 1
                if it == empty_byte:
                    domain_parts.append(domain_part)
                    domain_part = ''
                    flag = 0
                    it = 0  
                if byte == 0:
                    # iterate to end of domain msg (0x00 byte)
                    domain_parts.append(domain_part)
                    break
            else:
                 # first byte - empty
                flag = 1
                empty_byte = byte 

            it_end_dmn += 1

        

        #Qusestion type: first 2 bytes after domain bytes sequence
        q_type = data[it_end_dmn:it_end_dmn+2]  # Copyright - https://youtu.be/4I9LEY-q-co
        
        return (domain_parts, q_type)      

    def getZone(self, domain):
        zone_name = '.'.join(domain) # Add '.' in the end domain-name
        return self.zone_data[zone_name]

    def getAnswersCount(self, data):

        domain_parts, q_type = self.getQuestionDomain(data)
        
        QTYPE = ''
        if q_type == b'\x00\x01':
            QTYPE = 'a' # standart query for host resolving
        
        # Resolve zone using domain
        zone = self.getZone(domain_parts)
        return (zone['a'], QTYPE, domain_parts) 

    def buildQuery(self, domain, q_type):
        #TODO don't pass query type
        q_bytes = b''

        for part in domain:
            length = len(part) #countity of chars in part of domain
            #add length of part
            q_bytes += bytes([length])

            #Copyright https://youtu.be/4I9LEY-q-co
            for char in part:
            #add part like seq of chars cast to bytes
                q_bytes += ord(char).to_bytes(1, byteorder='big')

        if q_type == 'a':
            # QTYPE
            q_bytes += (1).to_bytes(2, byteorder='big')

        # QCLASS
        q_bytes += (1).to_bytes(2, byteorder='big')

        return q_bytes

    def recordToBytes(self, domain, query_type, query_ttl, query_addr):

        #Copyright https://youtu.be/4I9LEY-q-co
        query_bytes = b'\xc0\x0c'

        if query_type == 'a':
            query_bytes = query_bytes + bytes([0]) + bytes([1])

        query_bytes = query_bytes + bytes([0]) + bytes([1])

        query_bytes += int(query_ttl).to_bytes(4, byteorder='big')

        if query_type == 'a':
            query_bytes = query_bytes + bytes([0]) + bytes([4])
        
            for part in query_addr.split('.'):
                query_bytes += bytes([int(part)])

        return query_bytes

    def buildResponse(self, data):
        # ID (16 bit)
        qr_id = data[:2]
        
        # Flags (16 bit)
        flags = self.getFlags(data[2:4])
        
        # QDCOUNT (16 bits)
        QDCOUNT = b'\x00\x01'
        # ANCOUNT (16 bits)
        ANCOUNT = len(self.getAnswersCount(data[12:])[0]).to_bytes(2, byteorder='big') #Copyright https://youtu.be/4I9LEY-q-co
        # NSCOUNT (16 bits)
        NSCOUNT = (0).to_bytes(2, byteorder='big')
        # ARCOUNT (16 bits)
        ARCOUNT = (0).to_bytes(2, byteorder='big')

        dns_header = qr_id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
        
        #DNS body
        dns_body = b''

        #Get answer for query
        a_records, q_type, domain = self.getAnswersCount(data[12:])

        dns_question = self.buildQuery(domain, q_type)
        
        for record in a_records:
            dns_body += self.recordToBytes(domain, q_type, record["ttl"], record["value"])

        return dns_header + dns_question + dns_body

server = DNS_server()
print("Starting DNS server " + str(server.ip) 
      + " on port: " + str(server.port))

# Open socket
try: 
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.bind((server.ip, server.port))
except OSError as msg:
    print("The socket can't be open")
    sck.close()

# Run server
while 1:
    # Get query from dig socket
    data, addr = sck.recvfrom(512) #UDP msg length

    # Build response on the received query
    response = server.buildResponse(data)

    # Send response to dig socket
    sck.sendto(response, addr)