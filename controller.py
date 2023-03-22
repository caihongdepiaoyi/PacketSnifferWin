from PyQt5.QtWidgets import *
from ui import *
from sniffer import *
from pktParser import *
from scapy.layers import http
import psutil

class controller():
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None
    def LookupIface(self):
        c = []
        for interface, addrs in psutil.net_if_addrs().items():
            c.append(interface)
        return c
    def loadIface(self):
        ifaces  = self.LookupIface()
        #print(ifaces)
        self.ui.setAdapterIfaces(ifaces)

    def setSniffer(self):
        self.sniffer.filter = self.ui.filter
        self.sniffer.iface=self.ui.comboBoxIfaces.currentText()
        self.ui.iface = self.ui.comboBoxIfaces.currentText()

    def Start(self):
        self.ui.buttonStart.setEnabled(False)
        self.ui.buttonPause.setEnabled(True)
        self.ui.buttonSearch.setEnabled(True)
        self.ui.buttonFilter.setEnabled(False)
        #self.ui.button
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.setSniffer()
            self.sniffer.HandleSignal.connect(self.packetCallback)
            self.sniffer.start()
            print('start')
        elif self.sniffer.conditionFlag :
            if self.ui.iface != self.ui.comboBoxIfaces.currentText()  or self.sniffer.filter != self.ui.filter :
                self.setSniffer()
                self.ui.clearTable()
            self.sniffer.resume()
    def Stop(self):
        self.ui.buttonStart.setEnabled(True)
        self.ui.buttonPause.setEnabled(False)
        self.ui.buttonFilter.setEnabled(True)
        self.ui.buttonSearch.setEnabled(False)
        self.ui.Filter = None
        self.sniffer.Filter = None
        print("pause")
        self.sniffer.pause()

    def Save(self):
        try:
            row = self.ui.tableWidget.currentRow()
            packet = self.ui.packList[row].packet
            path, filetype = QtWidgets.QFileDialog.getSaveFileName(None,
                                    "选择保存路径",
                                    "./",
                                    "pcap文件(*.cap);;全部(*)")
            if path == "":
                return
            if os.path.exists(os.path.dirname(path)) == False:
                qmb = QMessageBox(None)
                qmb.setText("路径不存在")
                qmb.setWindowTitle("错误")
                qmb.exec_()
                return
            wrpcap(path,packet)
            qmb = QMessageBox(None)
            qmb.setText("保存成功")
            qmb.setWindowTitle("成功")
            qmb.exec_()
        except ImportError as  e:
            qmb = QMessageBox(None)
            qmb.setText(str(e))
            qmb.setWindowTitle("错误")
            qmb.exec_()

    def packetCallback(self,packet):
        if self.ui.filter ==  'http' or self.ui.filter ==  'https':
            if packet.haslayer('TCP') ==False:
                return
        if self.ui.traceProcess:
            if packet.haslayer('TCP'):
                port = netpidport(self.ui.pid)
                if packet['TCP'].sport in port or packet['TCP'].dport in port:
                    pass
                else:
                    return
            else:
                return
        res = []
        myPacket = pktParser()
        myPacket.parse(packet,self.ui.startTime)
        packetTime = myPacket.packTimne
        lens = myPacket.lens
        src = myPacket.layer_3['src']
        dst = myPacket.layer_3['dst']
        type = None
        info = None
        if myPacket.layer_1['name'] is not None:
            type = myPacket.layer_1['name']
            info = myPacket.layer_1['info']
        elif myPacket.layer_1s['name'] is not None:
            type = myPacket.layer_1s['name']
            info = myPacket.layer_1s['info']
        elif myPacket.layer_2['name'] is not None:
            type = myPacket.layer_2['name']
            info = myPacket.layer_2['info']
        elif myPacket.layer_3['name'] is not None:
            type = myPacket.layer_3['name']
            info = myPacket.layer_3['info']
        res.append(packetTime)
        res.append(src)
        res.append(dst)
        res.append(type)
        res.append(lens)
        res.append(info)
        res.append(myPacket)
        self.ui.setTableItems(res)

    def setConnection(self):
        self.ui.buttonStart.clicked.connect(self.Start)    
        self.ui.buttonPause.clicked.connect(self.Stop)
        self.ui.buttonFilter.clicked.connect(self.ui.Filter)
        self.ui.tableWidget.itemClicked.connect(self.ui.showItemDetail)
        self.ui.buttonSearch.clicked.connect(self.ui.Search)
        self.ui.tableWidget.customContextMenuRequested.connect(self.ui.showContextMenu)
        self.ui.TraceAction.triggered.connect(self.ui.Trace)
        self.ui.saveAction.triggered.connect(self.Save)

if __name__ == "__main__":
    #c = controller()
    #c.LookupIface()
    pass