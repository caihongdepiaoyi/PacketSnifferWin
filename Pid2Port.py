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

#print(get_process_network(16896))
#sniff(prn=packet_callback,filter=f"tcp")
