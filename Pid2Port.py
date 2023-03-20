import psutil
from scapy.all import *
conf.iface = "WLAN"

### 根据PID获取对应端口 / 根据端口获取进程的PID
### 实现获取进程列表，跟踪特定程序的网络流量

def ifProcessRunning(process_name):
    pl = psutil.pids()
    result = "PROCESS_IS_NOT_RUNNING"
    for pid in pl:
        if (psutil.Process(pid).name() == process_name):
            if isinstance(pid, int):
                result = "PROCESS_IS_RUNNING"
    return result
def netpidport(pid: int):
    """根据pid寻找该进程对应的端口"""
    alist = set([])
    # 获取当前的网络连接信息
    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.pid == pid:
            alist.add(con_info.laddr.port)
    return alist
def netportpid(port: int):
    """根据端口寻找该进程对应的pid"""
    adict = {}
    # 获取当前的网络连接信息
    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.laddr.port == port:
            adict[port] = con_info.pid
    return adict
def porttopid(port: int):
    """根据端口判断是否存在程序"""
    isrunning = False
    # 获取当前的网络连接信息
    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.laddr.port == port:
            isrunning = True
    return isrunning

def get_process_network(pid):
    process = psutil.Process(pid)
    connections = process.connections()
    network = []
    for conn in connections:
        if conn.type == psutil.AF_INET or conn.type == psutil.AF_INET6:
            network.append((conn.type, conn.laddr, conn.raddr, conn.status))
    return network

# 获取所有进程的信息
processes = psutil.process_iter()

processNetInfo = {}
# 遍历所有进程并打印信息
for p in processes:
    try:
        # 获取进程的详细信息
        process_info = p.as_dict(attrs=['pid', 'name', 'username'])
        port = netpidport(process_info['pid'])
        # 打印进程信息
        if len(port) != 0:
            print(f"PID: {process_info['pid']}  Name: {process_info['name']} Port: {port} User: {process_info['username']}")
            processNetInfo.update({process_info['pid']:{
                'pid': process_info['pid'],
                'name':process_info['name'],
                'port':port,
                'user':process_info['username']
                }})
        else:
            pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess ):
        # 忽略无法访问的进程
        pass

def packet_callback(packet):
    if packet[TCP].sport in processNetInfo[5692]['port'] :
        print("output: ", packet.summary())
    elif packet[TCP].dport in processNetInfo[5692]['port'] :
        print("input: ", packet.summary())
    #print(packet.show())
    pass

#print(get_process_network(16896))
sniff(prn=packet_callback,filter=f"tcp")
