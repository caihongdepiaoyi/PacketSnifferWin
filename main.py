import sys
import time
import binascii
from PySide2 import *
from scapy.all import *

# Every Qt application must have one and only one QApplication object;
# it receives the command line arguments passed to the script, as they
# can be used to customize the application's appearance and behavior
qt_app = QApplication(sys.argv)
global_pkt_list = []

# Try to redirect hexdump()'s output, but failed!Why? T_T
class redirect_output:
    def __init__(self):
        self.str = ''
    def write(self, s):
        self.str += s
    def show(self):
        return self.str

class Sniffer(QThread):
    pkt_arrive = Signal(str)
    bGo = True
    filter = None
    iface = 'eth0'

    def __init__(self, parent=None):
        QThread.__init__(self, parent)
        # self.pkt_arrive.connect(OnPktArrive)

    def run(self):
        # self.emit(SIGNAL("pkt_arrive(str)"), "pkt")
        while (self.bGo):
            p = sniff(count=1, filter = self.filter)
            global_pkt_list.append(p[0])
            self.pkt_arrive.emit((p[0].summary()))

    def go(self):
        self.bGo = True
        self.start()

    def stop(self):
        print("Sniffer got exit message")
        self.bGo = False

class PktListItem(QListWidgetItem):
    def __init__(self, pkt=None, num=None):
        QListWidgetItem.__init__(self)
        self.pkt = pkt
        self.num = num

class MainWindow(QWidget):
    ''' An example of PySide absolute positioning; the main window
        inherits from QWidget, a convenient widget for an empty window. '''
    number = 0
    def __init__(self):
        QWidget.__init__(self)
        self.setWindowTitle('J_Sniffer')
        self.setMinimumSize(800, 500)

        # set layout
        self.main_layout = QVBoxLayout()
        # edit and btn
        self.layout1 = QHBoxLayout()

        self.Label_Iface = QLabel("Iface", self)
        self.layout1.addWidget(self.Label_Iface)
        self.TextBox_Iface = QLineEdit(self)
        self.TextBox_Iface.setPlaceholderText("Choose network interface")
        self.layout1.addWidget(self.TextBox_Iface)

        self.Label_Fliter = QLabel("Filter", self)
        self.layout1.addWidget(self.Label_Fliter)
        self.TextBox_Filter = QLineEdit(self)
        self.layout1.addWidget(self.TextBox_Filter)

        self.layout1.addStretch(1)
        self.Btn_Start = QPushButton("&Start", self)
        self.layout1.addWidget(self.Btn_Start)

        self.main_layout.addLayout(self.layout1)

        # List to show packets
        self.List_Pkt = QListWidget(self)
        self.main_layout.addWidget(self.List_Pkt)

        # Tree to see pkt's detail
        self.Tree = QTreeWidget(self)
        self.main_layout.addWidget(self.Tree)
        self.Tree.setColumnCount(2)
        self.Tree.setHeaderLabels(['Key', 'Value'])

        self.setLayout(self.main_layout)

        # create signal and sniff thread
        self.thread = Sniffer()
        self.connect(self.Btn_Start, SIGNAL("clicked()"), self.Sniff)
        # self.connect(self.thread, SIGNAL("pkt_arrive(str)"), self.OnPktArrive) Connot work!
        self.thread.pkt_arrive.connect(self.OnPktArrive)
        self.List_Pkt.currentItemChanged.connect(self.On_ItemChanged)

    @Slot(str)
    def OnPktArrive(self, pkt):
        print("received pkt arrive signal")

        #p = Ether(pkt) #only Ethernet now, 802.11 may be crash!
        item = PktListItem(num = self.number)
        item.setText(str(self.number) + '\t' + pkt)
        self.List_Pkt.addItem(item)
        self.number += 1

    @Slot()
    def Sniff(self):
        print(self.Btn_Start.text())
        if self.Btn_Start.text() == '&Start':
            self.Btn_Start.setText("&Stop")
            self.thread.filter = self.TextBox_Filter.text()
            self.thread.iface = self.TextBox_Iface.text()
            self.thread.go()
        else:
            self.Btn_Start.setText("&Start")
            self.thread.stop()

    def On_ItemChanged(self, curr, prev):
        print(curr.num)
        self.Tree.clear()
        p = global_pkt_list[curr.num]
        root1 = QTreeWidgetItem(self.Tree)
        if (p.haslayer(Ether)):
            root1.setText(0, 'Ethernet:')
            child1_1 = QTreeWidgetItem(root1)
            child1_1.setText(0, 'dst')
            child1_1.setText(1, p.dst)
            child1_2 = QTreeWidgetItem(root1)
            child1_2.setText(0, 'src')
            child1_2.setText(1, p.src)
            child1_3 = QTreeWidgetItem(root1)
            child1_3.setText(0, 'type')
            child1_3.setText(1, hex(p.type))
            p = p.getlayer(1)
            if (p.haslayer(IP)):
                self._SetIPTree(p)
                p = p.getlayer(1)
                if (p.haslayer(ICMP)):
                    self._SetICMPTree(p)
                elif (p.haslayer(TCP)):
                    pass
                else:
                    pass
            elif (p.haslayer(IPv6)):
                pass
        else:
            root1.setText(0, 'Not Ethernet')
            root1.setText(1, hexdump(p))

    def _SetIPTree(self, p):
        root2 = QTreeWidgetItem(self.Tree)
        root2.setText(0, 'IPv4')
        child2_1 = QTreeWidgetItem(root2)
        child2_1.setText(0, 'Version')
        child2_1.setText(1, str(p.version))
        child2_2 = QTreeWidgetItem(root2)
        child2_2.setText(0, 'ihl(Header Length)')
        child2_2.setText(1, str(p.ihl))
        child2_3 = QTreeWidgetItem(root2)
        child2_3.setText(0, 'tos')
        child2_3.setText(1, str(p.tos))
        child2_4 = QTreeWidgetItem(root2)
        child2_4.setText(0, 'len')
        child2_4.setText(1, str(p.len))
        child2_5 = QTreeWidgetItem(root2)
        child2_5.setText(0, 'id')
        child2_5.setText(1, str(p.id))
        child2_6 = QTreeWidgetItem(root2)
        child2_6.setText(0, 'flags')
        child2_6.setText(1, str(p.flags))
        child2_7 = QTreeWidgetItem(root2)
        child2_7.setText(0, 'frag')
        child2_7.setText(1, str(p.frag))
        child2_8 = QTreeWidgetItem(root2)
        child2_8.setText(0, 'TTL')
        child2_8.setText(1, str(p.ttl))
        child2_9 = QTreeWidgetItem(root2)
        child2_9.setText(0, 'protocol')
        child2_9.setText(1, str(p.proto))
        child2_10 = QTreeWidgetItem(root2)
        child2_10.setText(0, 'checksum')
        child2_10.setText(1, str(p.chksum))
        child2_11 = QTreeWidgetItem(root2)
        child2_11.setText(0, 'src')
        child2_11.setText(1, str(p.src))
        child2_12 = QTreeWidgetItem(root2)
        child2_12.setText(0, 'dst')
        child2_12.setText(1, str(p.dst))

    def _SetICMPTree(self, p):
        root3 = QTreeWidgetItem(self.Tree)
        root3.setText(0, 'ICMP')
        child3_1 = QTreeWidgetItem(root3)
        child3_1.setText(0, 'Type')
        if (p.type == 8):
            child3_1.setText(1, 'echo request')
        elif (p.type == 0):
            child3_1.setText(1, 'echo reply')
        else:
            child3_1.setText(1, str(p.type))
        child3_2 = QTreeWidgetItem(root3)
        child3_2.setText(0, 'Code')
        child3_2.setText(1, str(p.code))
        child3_3 = QTreeWidgetItem(root3)
        child3_3.setText(0, 'Checksum')
        child3_3.setText(1, str(p.chksum))
        child3_4 = QTreeWidgetItem(root3)
        child3_4.setText(0, 'ID')
        child3_4.setText(1, str(p.id))
        child3_5 = QTreeWidgetItem(root3)
        child3_5.setText(0, 'Sequence number')
        child3_5.setText(1, str(p.seq))
        child3_6 = QTreeWidgetItem(root3)
        child3_6.setText(0, 'Data')
        child3_6.setText(1, binascii.b2a_hex(str(p.load)))

    def run(self):
        self.show()

if __name__ == '__main__':
    # Create an instance of the application window and run it
    win = MainWindow()
    win.run()
    qt_app.exec_()
