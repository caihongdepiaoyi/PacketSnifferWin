from scapy.all import *
#from scapy_http import http
# 配置嗅探器
conf.iface = "WLAN"

# 定义处理函数
def process_packet(packet):
    
    # 分析数据包
    if packet.haslayer(ARP):
        print("ARP")
    if packet.haslayer(UDP):
        print("UDP")
        packet.show2()
# 捕获数据包
sniff(prn=process_packet, count=10)
