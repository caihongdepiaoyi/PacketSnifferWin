from scapy.all import *

# 设置过滤规则，只捕获目标进程的流量
pid = 1216
filter_rule = "pid %d" % pid

# 绑定接口并设置过滤规则
sniffer = conf.L2listen(
    type=ETH_P_ALL,
    filter=filter_rule,
)

def packet_callback(packet):
    # 处理捕获到的数据包
    print(packet.summary())

# 开始捕获数据包并调用回调函数
sniff(opened_socket=sniffer, prn=packet_callback)