from scapy.all import *
#from scapy_http import http
# 配置嗅探器
conf.iface = "WLAN"

def LookupIface():
    eth_local = []
    a = repr(conf.route).split("\n")[1:]
    for x in a:
        b = re.search(r"[a-zA-Z](.*)[a-zA-Z]", x)
        eth_local.append(b.group())
    # 去重
    c = []
    c.append(eth_local[0])
    for i in range(0, len(eth_local), 1):
        m = 0
        for j in range(0, len(c), 1):
            if c[j] == eth_local[i]:
                m += 1
        if m == 0:
            c.append(eth_local[i])
    print(c)

# 定义处理函数
def process_packet(packet):
    try:
        type = packet.type
    except:
        type = 0
    print(type)
    if type == 0x800:
        print("type：IPv4(0x800)")
        print("version:%s" % packet[IP].version)
        print("src:%s -> dst:%s" % (packet[IP].src, packet[IP].dst))
    elif type == 0x806:
        print("协议类型(type)ARP(0x806)")
    else:
        pass
    
    if packet.haslayer("Raw"):
        print("Raw：%s" % packet[Raw].load.decode("utf-8", "ignore"))
    if packet.haslayer("Padding"):
        print("Padding：%s" % packet[Padding].load.decode("utf-8", "ignore"))

# 捕获数据包
LookupIface()
#show_interfaces()

sniff(prn=process_packet, count=10)

