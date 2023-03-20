from PyQt5.QtWidgets import *
from ui import *
from sniffer import *
from pktParser import *
from scapy.layers import http

class controller():
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None
    def LookupIface(self):
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
        return c
    def loadIface(self):
        ifaces  = self.LookupIface()
        self.ui.setAdapterIfaces(ifaces)

    def setSniffer(self):
        self.sniffer.filter = self.ui.filter
        self.sniffer.iface=self.ui.comboBoxIfaces.currentText()
        self.ui.iface = self.ui.comboBoxIfaces.currentText()

    def Start(self):
        self.ui.buttonStart.setEnabled(False)
        self.ui.buttonPause.setEnabled(True)
        print("start")
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.setSniffer()
            self.sniffer.HandleSignal.connect(self.packetCallback)
            self.sniffer.start()
            print('start sniffing')
        elif self.sniffer.conditionFlag :
            if self.ui.iface != self.ui.comboBoxIfaces.currentText()  or self.sniffer.filter != self.ui.filter :
                self.setSniffer()
                self.ui.clearTable()
            self.sniffer.resume()
    def Stop(self):
        self.ui.buttonStart.setEnabled(True)
        self.ui.buttonPause.setEnabled(False)
        print("pause")
        self.sniffer.pause()

    def PostFilter(self):
        self.ui.postFilter()

    def Filter(self):
        self.ui.buildFilter()

    def Trace(self):
        self.ui.Trace()

    def Save(self):
        pass

    def packetCallback(self,packet):
        if self.ui.filter ==  'http' or self.ui.filter ==  'https':
            if packet.haslayer('TCP') ==False:
                return            
        if packet.haslayer('SSL/TLS'):
            print("https")
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
        self.ui.buttonFilter.clicked.connect(self.Filter)
        self.ui.tableWidget.itemClicked.connect(self.ui.showItemDetail)
        self.ui.buttonPostFilter.clicked.connect(self.PostFilter)
        self.ui.tableWidget.customContextMenuRequested.connect(self.ui.showContextMenu)
        self.ui.TraceAction.triggered.connect(self.Trace)
        self.ui.saveAction.triggered.connect(self.Save)
        self.ui.buttonRe.clicked.connect(self.ui.Reset)

if __name__ == "__main__":
    c = controller()
    c.LookupIface()
    pass