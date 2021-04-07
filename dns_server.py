import socket
import json
import dnslib

#dig @127.0.0.1 pikabu.ru 
#dig @127.0.0.1 facebook.com
#dig @127.0.0.1 habr.com 
#dig @127.0.0.1 linkedin.com
#dig @127.0.0.1 habr.com TXT habr.com A
#dig @127.0.0.1 linkedin.com TXT linkedin.com A

class DNS_server:

    # Server parameters
    ip = ''
    port = 0
    ip_master = ''
    port_master = 0
    # Map for storing JSON objects that represent zone info
    # key(domain-name) -> value(object)
    zone_data = {}
    blacklist_domains = {}
    blklst_response = 'default'
    # DNS record from master server
    master_zndata = b''
     
    def __init__(self):
        
        # Load default server params
        self.loadSettings()
        
        # Load file with DNS cache records    
        self.loadZones()
    
    # Load default settings
    def loadSettings(self):
        # Open JSON file
        json_obj = {}
        try:
            with open('conf.json') as conf:
                json_obj = json.load(conf)
        except IOError:
            print("[Error!] Can't open config file")

        # Parse fields
        self.ip = json_obj["ip"]
        self.port = json_obj["port"]
        self.ip_master = json_obj["ip_master"]
        self.port_master = json_obj["port_master"]
        self.blklst_response = json_obj["blacklist_message"]
        self.blacklist_domains = json_obj["blacklist"]

    # Load DNS file with zones that represends JSON objects
    def loadZones(self):
        
        json_objs = {} #array with dictionaries
        try:
            with open('dns.json') as dns_objs:
                json_objs = json.load(dns_objs)
        except IOError:
            print("[Eror!] Can't open local DNS zone file")

        zones = {} #array with json objects with key->"$original"

        for item in json_objs:
            for key in item:
                zone_name = item["$original"]
                zones[zone_name] = item
                break
        
        self.zone_data = zones

    # Build flags for DNS response
    # param: [2:4) segment DNS query bytes sequence, flag about domain status
    # return: 2 bytes of flags for DNS header response
    def getFlags(self, data, blacklist_flag):
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
        if blacklist_flag:
            RCODE = '0011'
        else:
            RCODE = '0000'

        res_byte1 = int(QR+Opcode+AA+TC+RD, 2).to_bytes(1, byteorder='big')
        res_byte2 = int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

        return res_byte1 + res_byte2

    # Return domain and qury type on current DNS query
    # param: [12:] bytes from DNS query that represends domain name and query type
    # return: list with querying domain parts and query type ('a' usually)
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

    # Return master server dns response on the quering domen_name
    # param: searching domain
    # return: seq of bytes with dns response (but with non-correct ID)
    def getZoneMaster(self, domain):
        
        # Copyright example https://stackoverflow.com/a/56129114
        forward_addr = (self.ip_master, self.port_master) # Master server dns and port

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            query = dnslib.DNSRecord.question(domain)
            client.sendto(bytes(query.pack()), forward_addr)
            data, _ = client.recvfrom(512)
            return data
        except OSError as msg:
            print("[Error!] Socket to master server can't be open")


    # Return DNS record by the domain name and blacklist status
    # params: list with domain parts 
    # return: json object by the domain key and flag-vars that check domain in blacklist
    def getZone(self, domain):
        
        zone_name = '.'.join(domain) # Join domain in str with '.' separs
        in_blacklist = False

        #Check domain in blacklist
        for item in self.blacklist_domains:
            if zone_name == item["domain"]:
                in_blacklist = True

        if zone_name in self.zone_data:
            return (self.zone_data[zone_name], in_blacklist)
        else:
            #If record not find in dns.json need request to 1.1.1.1 and get info
            self.master_zndata = self.getZoneMaster(zone_name)
            return ({}, in_blacklist) # return empty dic that means that record not search locally 

    # Return params for ANCOUNT and DNS query
    # params: [12:) DNS query offset in bytes
    # return: toupe, A-type DNS record, query type, list of domains parts
    def getAnswersCount(self, data):

        domain_parts, q_type = self.getQuestionDomain(data)
        
        QTYPE = ''
        if q_type == b'\x00\x01':
            QTYPE = 'a' # standart query for host resolving
        if q_type == b'\x00\x10':
            QTYPE = "TXT" # TXT query

        # Resolve zone using domain
        zone, flag = self.getZone(domain_parts)

        # Resolve DNS record type
        if bool(zone):
            if QTYPE == 'a':
                return (zone['a'], QTYPE, domain_parts, flag)
            else:
                # for TXT type
                return ({}, QTYPE, domain_parts, flag)
        else:
            #If zone not found locally
            return ({}, QTYPE, domain_parts, flag)
          
    # Build DNS query
    # params: list of domain parts, query type
    # return: dns query that contains from domain_lenght, parts, in bytes
    def buildQuery(self, domain, q_type):
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
        if q_type == 'TXT':
            # QTYPE - TXT
            q_bytes += b'\x00\x10'

        # QCLASS
        q_bytes += (1).to_bytes(2, byteorder='big')
        
        return q_bytes


    # Convert DNS body in bytes
    # params: str(type of quey), ttl(int), str(ip) addr
    # return: querying record in bytes
    # Use with A-responses. With TXT-responses not working, in this case using dnslib
    def recordToBytes(self, query_type, query_ttl, query_addr):
        #Copyright https://youtu.be/4I9LEY-q-co

        # Pointer do domain
        query_bytes = b'\xc0\x0c'

        # Response type
        if query_type == 'a':
            query_bytes = query_bytes + bytes([0]) + bytes([1])
        else:
            query_bytes = query_bytes + bytes([0]) + bytes([10])

        # CLASS
        query_bytes = query_bytes + bytes([0]) + bytes([1])

        # TTL
        if query_type == 'a':
            query_bytes += int(query_ttl).to_bytes(4, byteorder='big')
        else:
            query_bytes += int(255).to_bytes(4, byteorder='big')

        #RDLENGTH + RDATA    
        if query_type == 'a':
            #RDLENGTH
            query_bytes = query_bytes + bytes([0]) + bytes([4])

            #RDATA
            for part in query_addr.split('.'):
                query_bytes += bytes([int(part)])
        else: 
            #RDLENGTH
            RDLENGTH = len(query_addr)
            query_bytes += query_bytes + (0).to_bytes(2, byteorder='big')
            query_bytes += RDLENGTH.to_bytes(2, byteorder='big')

            #RDATA
            query_bytes += RDLENGTH.to_bytes(2, byteorder='big')
            query_bytes += bytes(query_addr, 'utf-8')

        return query_bytes
    
    # Return DNS package-response on socket query with TXT section
    # param: bytes of is socket-query, list with domain parts
    # return: dns package in bytes
    def txtAnswrDNS(self, query_id, domain_parts):
        # Get full domain
        domain_str = '.'.join(domain_parts)

        # Build TXT DNS answer
        q = int.from_bytes(query_id, byteorder='big')        

        header = dnslib.DNSHeader(id=q, qr=1,aa=1, ra=1) 
        question = dnslib.DNSQuestion(domain_str, 16)
        body = dnslib.RR(domain_str, rtype = 16, rdata=dnslib.TXT(self.blklst_response))

        # Build full package
        dns = dnslib.DNSRecord()
        dns.header = header
        dns.question = question
        dns.rr.append(body)
        
        return dns.pack()

    # Build respone in DNS query
    # params: sequence of bytes
    # return: DNS packages that consist of: dns header, question, body 
    def buildResponse(self, data):
        #Flag what tells about domain name status
        blcklst_flag = False

        # ID (16 bit)
        qr_id = data[:2]
        
        # Flags (16 bit)
        flags = self.getFlags(data[2:4], blcklst_flag)
        
        # QDCOUNT (16 bits)
        QDCOUNT = b'\x00\x01'
        # ANCOUNT (16 bits)
        ANCOUNT = b''
        if not bool(len(self.getAnswersCount(data[12:])[0])):
            #if getAnswersCount() return empty dic
            ANCOUNT = b'\x00\x01'
        else:
            ANCOUNT = len(self.getAnswersCount(data[12:])[0]).to_bytes(2, byteorder='big') #Copyright https://youtu.be/4I9LEY-q-co

        # NSCOUNT (16 bits)
        NSCOUNT = (0).to_bytes(2, byteorder='big')
        # ARCOUNT (16 bits)
        ARCOUNT = (0).to_bytes(2, byteorder='big')

        #Get answer for query
        records, q_type, domain, blcklst_flag = self.getAnswersCount(data[12:])
        
        if not bool(records) and blcklst_flag == False:
            # Searching domain not found in local DNS records. Return DNS package from  master server
            
            # Rewrite 2 first bytes in pckg from master server for correct client response
            buffer_1 = self.master_zndata[2:]
            buffer_2 = qr_id + buffer_1
            self.master_zndata = buffer_2

            return self.master_zndata

        if blcklst_flag:
            #Rewrite DNS header flags if domain in blacklist
            flags = self.getFlags(data[2:4], blcklst_flag)
        
        # Build DNS headers
        dns_header = qr_id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

        if blcklst_flag:
             # Server console print    
            print(self.blklst_response + ' ' + '.'.join(domain)) 

            # Build DNS package for blacklist domain query
            dns_question = self.buildQuery(domain, q_type)
            dns_body = b''
            if q_type == 'a':   
                # Build A DNS body
                dns_body = self.recordToBytes(q_type, 0, "0.0.0.0")
                return dns_header + dns_question + dns_body
            else:
                return self.txtAnswrDNS(qr_id, domain) 
        else:
            # Build normal DNS package
            
            # Build A DNS query
            dns_question = self.buildQuery(domain, q_type)

            # Build DNS body
            dns_body = b''
            for record in records:
                dns_body += self.recordToBytes(q_type, record["ttl"], record["value"])

            return dns_header + dns_question + dns_body

server = DNS_server()
print("Starting DNS server " + str(server.ip) + " on port: " + str(server.port) + " ..")

# Open socket
try: 
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.bind((server.ip, server.port))
except OSError as msg:
    print("[Error!] The socket can't be open")
    sck.close()

# Run server
while 1:
    # Get query from dig socket
    data, addr = sck.recvfrom(512)

    # Build response on the received query
    response = server.buildResponse(data)

    # Send response to dig socket
    sck.sendto(response, addr)