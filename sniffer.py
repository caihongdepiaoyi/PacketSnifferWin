from scapy.all import *
from scapy.layers import http
from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.packet.Packet)
    def __init__(self) -> None:
        super().__init__()
        self.filter = None
        self.iface = None
        self.conditionFlag = False
        self.mutex_1 = QMutex()
        self.cond = QWaitCondition()

    def run(self):
        load_layer("tls")
        while True :
            self.mutex_1.lock()
            if self.conditionFlag :
                self.cond.wait(self.mutex_1)
            sniff(filter=self.filter,iface=self.iface,prn=lambda x:self.HandleSignal.emit(x),count = 1,timeout=2)
            self.mutex_1.unlock()

    def pause(self):
        self.conditionFlag = True

    def resume(self):
        self.conditionFlag = False
        self.cond.wakeAll()   
