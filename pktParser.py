from scapy.all import *
from scapy.layers import http

def processStr(data):
    pattern = re.compile('^b\'(.*?)\'$', re.S)
    res = re.findall(pattern, str(data))
    final = re.split('\\\\r\\\\n', res[0])
    return final


class pktParser():
    def __init__(self):
        self.packTimne = None
        self.lens = None
        self.packet = None
        self.tcptrace = None
        self.layer_4 = {'name' : None, 'src': None, 'dst': None,'info':None}
        # IP ARP
        self.layer_3 = {'name' : None, 'src': None, 'dst': None,'version': None,\
            'ihl': None, 'tos': None, 'len': None, 'id': None, 'flag': None, 'chksum':None,\
            'opt':None, 'hwtype':None, 'ptype':None, 'hwlen':None,'type':None,'op':None,\
            'info':None, 'hwsrc':None, 'hwdst':None
            }
        #TCP UDP ICMP IGMP OTHERS
        self.layer_2 = {'name':None, 'src': None, 'dst': None, 'seq':None, 'ack':None,\
            'dataofs':None, 'reserved':None, 'flag':None, 'len':None, 'chksum':None,\
            'type':None, 'code':None, 'id':None,'info':None, 'window':None, 'tcptrace':None,\
            'tcpSdTrace': None, 'tcpRcTrace':None
            }
        #HTTP HTTPS
        self.layer_1 = {'type': None,'name':None, 'info':None, 'version': None, 'method':None, 'path': None, 'code': None, \
                        'date': None, 'last_Modified': None, 'connection': None, 'server': None,\
                        'accept': None, 'accept_language':None, 'cookie': None, 'user_agent':None,\
                        'accept_encoding':None }
        self.raw = None
    def parse(self,packet,startTime):
        self.packTimne = '{:.7f}'.format(time.time() - startTime)
        self.lens = str(len(packet))
        self.packet = packet
        self.parseEther(packet)
        if packet.haslayer(Raw):
            self.raw = packet['Raw'].load

    def parseEther(self, packet):
        if packet.haslayer('Ethernet'):
            self.layer_4['name'] = 'Ethernet'
            self.layer_4['src'] = packet.src
            self.layer_4['dst'] = packet.dst
            self.layer_4['info'] = ('Ethernet，源MAC地址(src)：'+ packet.src + '，目的MAC地址(dst)：'+packet.dst)
        elif packet.haslayer('Loopback'):
            self.layer_4['name'] = 'Loopback'
            self.layer_4['info'] = 'Loopback'
        self.parseNetWork(packet)
    def parseNetWork(self, packet):
        if packet.haslayer('IP'):
            if(packet['IP'].version == 4):
                self.layer_3['name'] = 'IPv4'
                self.layer_3['src'] = packet[IP].src
                self.layer_3['dst'] = packet[IP].dst
                self.layer_3['version'] = packet[IP].version
                self.layer_3['ihl'] = packet[IP].ihl
                self.layer_3['tos'] = packet[IP].tos
                self.layer_3['len'] = packet[IP].len
                self.layer_3['id'] = packet[IP].id
                self.layer_3['flag'] = packet[IP].flags
                self.layer_3['chksum'] = packet[IP].chksum
                self.layer_3['opt'] = packet[IP].options
                self.layer_3['info'] = ('IPv4，源地址(src)：'+packet[IP].src+'，目的地址(dst)：'+packet[IP].dst)
            elif(packet['IP'].version == 6):
                self.layer_3['name'] = 'IPv6'
                self.layer_3['src'] = packet[IPv6].src
                self.layer_3['dst'] = packet[IPv6].dst
                self.layer_3['version'] = packet[IPv6].version
                self.layer_3['info'] = ('IPv6，源地址(src)：'+packet[IPv6].src+'，目的地址(dst)：'+packet[IPv6].dst)
            self.parseTransport(packet)
        elif packet.haslayer('ARP'):
            self.layer_3['name'] = 'ARP'
            self.layer_3['src'] = packet[ARP].psrc
            self.layer_3['dst'] = packet[ARP].pdst
            self.layer_3['op'] = packet[ARP].op 
            self.layer_3['hwtype'] = packet[ARP].hwtype
            self.layer_3['ptype'] = packet[ARP].ptype
            self.layer_3['hwlen'] = packet[ARP].hwlen
            self.layer_3['len'] = packet[ARP].plen
            self.layer_3['hwsrc'] = packet[ARP].hwsrc
            self.layer_3['hwdst'] = packet[ARP].hwdst
            if packet[ARP].op == 1:  #request
                self.layer_3['info'] = ('Request: Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc))
            elif packet[ARP].op == 2:  #reply
                self.layer_3['info'] = ('Reply: %s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc))
            else:
                self.layer_3['info'] = ('操作: '+ packet[ARP].op )
        elif packet.haslayer('IPv6'):
            self.layer_3['name'] = 'IPv6'
            self.layer_3['src'] = packet[IPv6].src
            self.layer_3['dst'] = packet[IPv6].dst
            self.layer_3['version'] = packet[IPv6].version
            self.layer_3['info'] = ('IPv6，源地址(src)：'+packet[IPv6].src+'，目的地址(dst)：'+packet[IPv6].dst)
            self.parseTransport(packet)

    def parseTransport(self, packet):
        if packet.haslayer('TCP') :
            if packet.haslayer('IP'):
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IP].src, packet[IP].dst,packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IP].src,packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IP].dst, packet[TCP].dport))
            elif packet.haslayer('IPv6'):
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IPv6].src, packet[IPv6].dst,packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IPv6].src,packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IPv6].dst, packet[TCP].dport))
            self.layer_2['name'] = 'TCP'
            self.layer_2['src'] = packet[TCP].sport
            self.layer_2['dst'] = packet[TCP].dport
            self.layer_2['seq'] = packet[TCP].seq
            self.layer_2['ack'] = packet[TCP].ack
            self.layer_2['window'] = packet[TCP].window
            self.layer_2['dataofs'] = packet[TCP].dataofs
            self.layer_2['reserved'] = packet[TCP].reserved
            self.layer_2['flag'] = packet[TCP].flags
            self.layer_2['info'] = ('源端口%s -> 目的端口%s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
            self.parseHttp(packet)
        elif packet.haslayer('UDP'):
            self.layer_2['name'] = 'UDP'
            self.layer_2['src'] = packet[UDP].sport
            self.layer_2['dst'] = packet[UDP].dport
            self.layer_2['len'] = packet[UDP].len
            self.layer_2['chksum'] = packet[UDP].chksum
            self.layer_2['info'] =  ('源端口%s -> 目的端口%s 长度(len)：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
            if packet.haslayer('DNS'):
                self.parseDns(packet)
        elif packet.haslayer('ICMP'):
            self.layer_2['name'] = 'ICMP'
            self.layer_2['type'] = packet[ICMP].type
            self.layer_2['code'] = packet[ICMP].code
            self.layer_2['id'] = packet[ICMP].id
            self.layer_2['chksum'] = packet[ICMP].chksum
            self.layer_2['seq'] = packet[ICMP].seq
            if packet[ICMP].type == 8:
                self.layer_2['info'] = ('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
            elif packet[ICMP].type == 0:
                self.layer_2['info'] = ('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
            else:
                self.layer_2['info'] = ('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))      
        elif packet.haslayer('IGMP'):
            self.layer_2['name'] = 'IGMP'
            self.layer_2['len'] = packet[IPOption_Router_Alert].length
            self.layer_2['info'] = 'IGMP协议，等待补充'
        elif packet[IPv6].nh == 58:
                self.layer_2['name'] = 'ICMPv6'
                self.layer_2['info'] = 'ICMPv6协议，等待补充'
        else:
            self.layer_2['name'] = str(packet[IPv6].nh)
            self.layer_2['info'] = '未知协议'
    def parseDns(self, packet):
        self.layer_1['name'] ='DNS'
        if packet[DNS].opcode == 0:#Query
            tmp = '??'
            if packet[DNS].qd :
                tmp = bytes.decode(packet[DNS].qd.qname)
            self.layer_1['info'] = ('源端口：%s -> 目的端口%s 长度(len)：%s DNS 查询: %s 在哪里' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len,tmp))
        else:
            self.layer_1['info'] = ('源端口：%s -> 目的端口%s 长度(len)：%s DNS 回答' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
    def parseHttp(self, packet):
        self.layer_1['info'] = ''
        if packet.haslayer('HTTP'):
            try:
                self.layer_1['name'] ='HTTP'
                '''
                self.layer_1 = {'type': None,'name':None, 'info':None, 'version': None, 'method':None, 'path': None, 'code': None, \
                        'date': None, 'last_Modified': None, 'connection': None, 'server': None,\
                        'accept': None, 'accept_language':None, 'cookie': None, 'user_agent':None,\
                        'accept_encoding':None }
                '''
                if packet.haslayer(http.HTTPRequest):
                    self.layer_1['version'] = packet[http.HTTPRequest].fields['Http_Version'].decode()
                    self.layer_1['info'] = 'httpRequest'
                    self.layer_1['type'] = 1
                    self.layer_1['method'] = packet[http.HTTPRequest].fields['Method'].decode()
                    self.layer_1['path'] = packet[http.HTTPRequest].fields['Path'].decode()
                    self.layer_1['connection'] = packet[http.HTTPRequest].fields['Connection'].decode()
                    self.layer_1['accept'] = packet[http.HTTPRequest].fields['Accept'].decode()
                    self.layer_1['accept_language'] = packet[http.HTTPRequest].fields['Accept_Language'].decode()
                    self.layer_1['cookie'] = packet[http.HTTPRequest].fields['Cookie'].decode()
                    self.layer_1['user_agent'] = packet[http.HTTPRequest].fields['User_Agent'].decode()
                    self.layer_1['accept_encoding'] = packet[http.HTTPRequest].fields['Accept_Encoding'].decode()
                elif packet.haslayer(http.HTTPResponse):
                    self.layer_1['version'] = packet[http.HTTPResponse].fields['Http_Version'].decode()
                    self.layer_1['info'] = 'httpResponse'
                    self.layer_1['type'] = 0
                    self.layer_1['code'] = packet[http.HTTPResponse].fields['Status_Code'].decode()
                    self.layer_1['connection'] = packet[http.HTTPResponse].fields['Connection'].decode()
                    self.layer_1['date'] = packet[http.HTTPResponse].fields['Date'].decode()
                    self.layer_1['last_Modified'] = packet[http.HTTPResponse].fields['Last_Modified'].decode()
                    self.layer_1['server'] = packet[http.HTTPResponse].fields['Server'].decode()
            except:
                pass
        
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            self.layer_1['name'] ='HTTPS'
            self.layer_1['info'] = ('%s -> %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
        
def parse(packet):
    if packet.haslayer('Ethernet'):
        #print(packet['Ethernet'].dst)
        if packet.haslayer('IP'):
            #print(packet['IP'].version)
            if packet.haslayer('TCP'):
                pass
                #print(packet['TCP'].sport)
            elif packet.haslayer('UDP'):
                pass
                #print(packet['UDP'].dport)
            if packet.haslayer('HTTP'):
                #print(packet['HTTP'].show())
                print(packet['HTTP'].fields)
                http_header = packet['HTTP'].fields
                try:
                    print(http_header['Http_Version'])
                except:
                    pass
                #headers = http_header['Headers']
                #print(headers)
            if packet.haslayer(http.HTTPRequest):
                print("*********request******")
                http_name = 'HTTP Request'
                http_header = packet[http.HTTPRequest].fields
                try:
                    print(http_header['Http_Version'])
                except:
                    pass
                #headers = http_header['Headers']
                
            elif packet.haslayer(http.HTTPResponse):
                print("*********response******")
                http_name = 'HTTP Response'
                http_header = packet[http.HTTPResponse].fields
                try:
                    print(http_header['Http_Version'])
                except:
                    pass
                #headers = http_header['Headers']
                
                if 'Raw' in packet:
                    load = packet['Raw'].load
                    items = processStr(load)
                    for i in items:
                        print(i)

if __name__ == "__main__":
    sniff(iface='WLAN',prn=parse,count = 500)