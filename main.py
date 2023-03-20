from ui import *
import sys
from controller import *

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(style)
    app_icon = QIcon('./static/my_icon.png')
    app.setWindowIcon(app_icon)
    ui = UI()
    MainWindow = QtWidgets.QMainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    ctrl = controller(ui)
    ctrl.loadIface()
    ctrl.setConnection()
    sys.exit(app.exec_())