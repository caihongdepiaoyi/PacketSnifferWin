from PyQt5.QtWidgets import *
from ui import *
from sniffer import *
class controller():
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None
    def LookupIface(self):
        c = []
        for i in repr(conf.route).split('\n')[1:]:
            tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]',i).group()[0:44].rstrip()
            if len(tmp)>0:
                c.append(tmp)
        c = list(set(c))
        return c
    def loadIface(self):
        ifaces  = self.LookupIface()
        self.ui.setAdapterIfaces(ifaces)

    def setSniffer(self):
        self.sniffer.filter = self.ui.filter
        self.sniffer.iface=self.ui.comboBoxIfaces.currentText()
        self.ui.iface = self.ui.comboBoxIfaces.currentText()

    def Start(self):
        print("start")
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.setSniffer()
            self.sniffer.HandleSignal.connect(self.myCallBack)
            self.sniffer.start()
            print('start sniffing')
        elif self.sniffer.conditionFlag :
            if self.ui.iface != self.ui.comboBoxIfaces.currentText()  or self.sniffer.filter != self.ui.filter :
                self.setSniffer()
                self.ui.clearTable()
            self.sniffer.resume()
    def Stop(self):
        pass
    def Filter(self):
        pass
    def PostFilter(self):
        pass
    def Trace(self):
        pass
    def Save(self):
        pass
    def myCallBack(self,packet):
        pass

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