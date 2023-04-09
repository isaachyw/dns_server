import socket
import glob
import json


def load_zone():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zonefile in zonefiles:
        with open(zonefile, 'r') as f:
            data = json.load(f)
            zonename = data['$origin']
            jsonzone[zonename] = data
    return jsonzone


def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)+"."
    return zonedata[zone_name]


zonedata = load_zone()


def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''
    QR = '1'
    OPCODE = ''
    for i in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << i))

    AA = '1'
    TC = '0'
    RD = '0'
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
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1
    questiontype = data[y:y+2]
    return (domainparts, questiontype)


def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'
    zone = getzone(domain)
    return (zone[qt], qt, domain)


def buildresponse(data):
    TransactionID = data[:2]

    Flags = getflags(data[2:4])

    QDCOUNT = b'\x00\x01'
    getquestiondomain(data[12:])
    getrecs(data[12:])
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''
    records, rectype, domainname = getrecs(data[12:])
    dnsquestion = buildquestion(domainname, rectype)


def buildquestion(domainname, rectype):
    dnsquestion = b''
    for part in domainname:
        dnsquestion += len(part).to_bytes(1, byteorder='big')
        dnsquestion += bytes(part, 'utf-8')
    dnsquestion += b'\x00'
    if rectype == 'a':
        dnsquestion += b'\x00\x01'
    dnsquestion += b'\x00\x01'
    return dnsquestion


port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))
while True:
    data, addr = sock.recvfrom(1024)
    r = buildresponse(data)
    sock.sendto(r, addr)
